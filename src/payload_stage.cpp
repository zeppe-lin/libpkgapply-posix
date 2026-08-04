// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/payload_stage.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace pkgapply::posix {
namespace {

class unique_fd final {
public:
  explicit unique_fd(int value = -1) noexcept : value_(value) {}
  unique_fd(const unique_fd&) = delete;
  unique_fd& operator=(const unique_fd&) = delete;
  unique_fd(unique_fd&& other) noexcept : value_(other.release()) {}
  unique_fd& operator=(unique_fd&& other) noexcept
  {
    if (this != &other) {
      reset();
      value_ = other.release();
    }
    return *this;
  }
  ~unique_fd() { reset(); }
  [[nodiscard]] int get() const noexcept { return value_; }
  [[nodiscard]] int release() noexcept
  {
    const int result = value_;
    value_ = -1;
    return result;
  }
  void reset(int value = -1) noexcept
  {
    if (value_ >= 0)
      static_cast<void>(::close(value_));
    value_ = value;
  }
private:
  int value_;
};

struct evp_context_deleter final {
  void operator()(EVP_MD_CTX* context) const noexcept
  {
    EVP_MD_CTX_free(context);
  }
};

[[noreturn]] void
throw_error(payload_stage_error_code code,
            int system_error,
            std::string message)
{
  if (system_error != 0) {
    message += ": ";
    message += std::strerror(system_error);
  }
  throw payload_stage_error(code, system_error, std::move(message));
}

int
cloexec_flag() noexcept
{
#ifdef O_CLOEXEC
  return O_CLOEXEC;
#else
  return 0;
#endif
}

int
nofollow_flag() noexcept
{
#ifdef O_NOFOLLOW
  return O_NOFOLLOW;
#else
  return 0;
#endif
}

void
set_close_on_exec(int fd, payload_stage_error_code code)
{
#ifndef O_CLOEXEC
  const int flags = ::fcntl(fd, F_GETFD);
  if (flags < 0 || ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
    throw_error(code, errno, "cannot set close-on-exec on payload descriptor");
#else
  static_cast<void>(fd);
  static_cast<void>(code);
#endif
}

int
open_path(const char* path, int flags)
{
  for (;;) {
    const int result = ::open(path, flags);
    if (result >= 0 || errno != EINTR)
      return result;
  }
}

int
open_at(int directory_fd, const char* path, int flags, mode_t mode = 0)
{
  for (;;) {
    const int result = mode == 0
        ? ::openat(directory_fd, path, flags)
        : ::openat(directory_fd, path, flags, mode);
    if (result >= 0 || errno != EINTR)
      return result;
  }
}

void
require_directory(int fd, payload_stage_error_code code, std::string_view what)
{
  struct stat status {};
  if (::fstat(fd, &status) != 0)
    throw_error(code, errno, "cannot inspect " + std::string(what));
  if (!S_ISDIR(status.st_mode))
    throw_error(code, 0, std::string(what) + " is not a directory");
}

int
duplicate_fd(int fd, payload_stage_error_code code)
{
#ifdef F_DUPFD_CLOEXEC
  const int duplicate = ::fcntl(fd, F_DUPFD_CLOEXEC, 0);
#else
  const int duplicate = ::dup(fd);
#endif
  if (duplicate < 0)
    throw_error(code, errno, "cannot duplicate payload directory descriptor");
  set_close_on_exec(duplicate, code);
  return duplicate;
}

unique_fd
lock_stage(int directory_fd, short type, bool create)
{
  const int flags = O_RDWR | cloexec_flag() | nofollow_flag() |
      (create ? O_CREAT : 0);
  unique_fd lock(open_at(
      directory_fd, "lock-v1", flags, 0600));
  if (lock.get() < 0)
    throw_error(payload_stage_error_code::stage_locked, errno,
                "cannot open private payload-stage lock");
  set_close_on_exec(lock.get(), payload_stage_error_code::stage_locked);
  struct stat status {};
  if (::fstat(lock.get(), &status) != 0 || !S_ISREG(status.st_mode))
    throw_error(payload_stage_error_code::stage_locked,
                errno, "private payload-stage lock is not a regular file");
  struct flock record {};
  record.l_type = type;
  record.l_whence = SEEK_SET;
  record.l_start = 0;
  record.l_len = 0;
#ifdef F_OFD_SETLK
  constexpr int lock_command = F_OFD_SETLK;
#else
  constexpr int lock_command = F_SETLK;
#endif
  if (::fcntl(lock.get(), lock_command, &record) != 0)
    throw_error(payload_stage_error_code::stage_locked, errno,
                "cannot lock private payload stage");
  return lock;
}

void
synchronize_fd(int fd,
               payload_stage_error_code code,
               std::string_view message)
{
  for (;;) {
    if (::fsync(fd) == 0)
      return;
    if (errno != EINTR)
      throw_error(code, errno, std::string(message));
  }
}

void
write_all(int fd, const std::byte* data, std::size_t size)
{
  std::size_t offset = 0;
  while (offset < size) {
    const ssize_t result = ::write(fd, data + offset, size - offset);
    if (result < 0) {
      if (errno == EINTR)
        continue;
      throw_error(payload_stage_error_code::entry_write_failed, errno,
                  "cannot write private payload");
    }
    if (result == 0)
      throw_error(payload_stage_error_code::entry_write_failed, 0,
                  "private payload write made no progress");
    offset += static_cast<std::size_t>(result);
  }
}

void
write_all(int fd, const std::vector<std::byte>& bytes)
{
  write_all(fd, bytes.data(), bytes.size());
}

std::vector<std::byte>
read_file(int directory_fd,
          const std::string& name,
          payload_stage_error_code open_code,
          payload_stage_error_code read_code,
          std::size_t maximum)
{
  unique_fd file(open_at(
      directory_fd, name.c_str(),
      O_RDONLY | cloexec_flag() | nofollow_flag()));
  if (file.get() < 0)
    throw_error(open_code, errno, "cannot open private payload record");
  set_close_on_exec(file.get(), open_code);

  struct stat status {};
  if (::fstat(file.get(), &status) != 0)
    throw_error(read_code, errno, "cannot inspect private payload record");
  if (!S_ISREG(status.st_mode) || status.st_size < 0 ||
      static_cast<std::uint64_t>(status.st_size) > maximum)
  {
    throw_error(payload_stage_error_code::stage_invalid, 0,
                "private payload record has an invalid file type or size");
  }

  std::vector<std::byte> bytes(static_cast<std::size_t>(status.st_size));
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t result = ::read(
        file.get(), bytes.data() + offset, bytes.size() - offset);
    if (result < 0) {
      if (errno == EINTR)
        continue;
      throw_error(read_code, errno, "cannot read private payload record");
    }
    if (result == 0)
      throw_error(payload_stage_error_code::stage_invalid, 0,
                  "private payload record was truncated while reading");
    offset += static_cast<std::size_t>(result);
  }
  std::byte probe{};
  for (;;) {
    const ssize_t result = ::read(file.get(), &probe, 1);
    if (result < 0 && errno == EINTR)
      continue;
    if (result < 0)
      throw_error(read_code, errno, "cannot finish reading payload record");
    if (result != 0)
      throw_error(payload_stage_error_code::stage_invalid, 0,
                  "private payload record changed size while reading");
    break;
  }
  return bytes;
}

void
append_u16(std::vector<std::byte>& bytes, std::uint16_t value)
{
  bytes.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
  bytes.push_back(static_cast<std::byte>(value & 0xffU));
}

void
append_u64(std::vector<std::byte>& bytes, std::uint64_t value)
{
  for (int shift = 56; shift >= 0; shift -= 8)
    bytes.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
}

void
append_string(std::vector<std::byte>& bytes, const std::string& value)
{
  if (value.size() > std::numeric_limits<std::uint16_t>::max())
    throw_error(payload_stage_error_code::binding_mismatch, EOVERFLOW,
                "payload binding string is too large");
  append_u16(bytes, static_cast<std::uint16_t>(value.size()));
  for (const unsigned char byte : value)
    bytes.push_back(static_cast<std::byte>(byte));
}

std::string
hexadecimal(const std::uint8_t* bytes, std::size_t size)
{
  static constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(size * 2U);
  for (std::size_t index = 0; index < size; ++index) {
    result.push_back(digits[bytes[index] >> 4U]);
    result.push_back(digits[bytes[index] & 0x0fU]);
  }
  return result;
}

std::array<std::uint8_t, 32>
sha256_bytes(const std::byte* data, std::size_t size)
{
  std::unique_ptr<EVP_MD_CTX, evp_context_deleter> context(EVP_MD_CTX_new());
  if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
      (size != 0 && EVP_DigestUpdate(context.get(), data, size) != 1))
  {
    throw_error(payload_stage_error_code::entry_content_mismatch, 0,
                "cannot initialize private payload digest");
  }
  std::array<std::uint8_t, 32> digest{};
  unsigned int digest_size = 0;
  if (EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) != 1 ||
      digest_size != digest.size())
  {
    throw_error(payload_stage_error_code::entry_content_mismatch, 0,
                "cannot finalize private payload digest");
  }
  return digest;
}

std::array<std::uint8_t, 32>
sha256_file(int fd)
{
  std::unique_ptr<EVP_MD_CTX, evp_context_deleter> context(EVP_MD_CTX_new());
  if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
    throw_error(payload_stage_error_code::entry_content_mismatch, 0,
                "cannot initialize staged payload digest");

  std::array<std::byte, 64U * 1024U> buffer{};
  for (;;) {
    const ssize_t result = ::read(fd, buffer.data(), buffer.size());
    if (result < 0) {
      if (errno == EINTR)
        continue;
      throw_error(payload_stage_error_code::entry_read_failed, errno,
                  "cannot hash staged payload");
    }
    if (result == 0)
      break;
    if (EVP_DigestUpdate(
            context.get(), buffer.data(), static_cast<std::size_t>(result)) != 1)
    {
      throw_error(payload_stage_error_code::entry_content_mismatch, 0,
                  "cannot update staged payload digest");
    }
  }

  std::array<std::uint8_t, 32> digest{};
  unsigned int digest_size = 0;
  if (EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) != 1 ||
      digest_size != digest.size())
  {
    throw_error(payload_stage_error_code::entry_content_mismatch, 0,
                "cannot finalize staged payload digest");
  }
  return digest;
}

std::string
digest_text(const std::array<std::uint8_t, 32>& digest)
{
  return "v1:sha256:" + hexadecimal(digest.data(), digest.size());
}

struct expected_payload final {
  pkgimage::entry_id id;
  std::string path;
  std::uint64_t size;
  std::vector<std::uint8_t> digest;
};

std::vector<expected_payload>
expected_payloads(const pkgimage::package_image& image,
                  const pkgimage::entry_selection& selection)
{
  selection.validate(image);
  std::vector<expected_payload> result;
  result.reserve(selection.size());
  for (const auto& image_entry : image.entries()) {
    if (!selection.contains(image_entry.id))
      continue;
    if (image_entry.type != pkgimage::entry_type::regular ||
        !image_entry.regular_content)
    {
      throw_error(payload_stage_error_code::binding_mismatch, 0,
                  "payload selection contains no exact regular image entry");
    }
    const auto& content = image_entry.regular_content->bytes();
    if (content.size() != 32U)
      throw_error(payload_stage_error_code::binding_mismatch, 0,
                  "regular image entry has no SHA-256 content identity");
    result.push_back({
        image_entry.id, image_entry.path.string(), image_entry.size,
        std::vector<std::uint8_t>(content.begin(), content.end())});
  }
  if (result.size() != selection.size())
    throw_error(payload_stage_error_code::binding_mismatch, 0,
                "payload selection count differs from the bound image");
  std::sort(result.begin(), result.end(), [](const auto& lhs, const auto& rhs) {
    return lhs.id < rhs.id;
  });
  if (std::adjacent_find(
          result.begin(), result.end(),
          [](const auto& lhs, const auto& rhs) { return lhs.id == rhs.id; }) !=
      result.end())
  {
    throw_error(payload_stage_error_code::binding_mismatch, 0,
                "payload selection contains duplicate entry identifiers");
  }
  return result;
}

std::vector<std::byte>
binding_encoding(const application_attempt& attempt,
                 const pkgimage::package_image& image,
                 const std::vector<expected_payload>& entries)
{
  std::vector<std::byte> bytes;
  const std::array<unsigned char, 8> magic = {
      'P', 'K', 'G', 'A', 'P', 'S', 'T', 'G'};
  for (const auto byte : magic)
    bytes.push_back(static_cast<std::byte>(byte));
  append_u16(bytes, 1);
  append_string(bytes, attempt.identity().string());
  append_string(bytes, attempt.request().string());
  append_string(bytes, attempt.target().string());
  append_string(bytes, attempt.backend().string());
  for (const auto byte : attempt.nonce().bytes())
    bytes.push_back(static_cast<std::byte>(byte));
  append_string(bytes, image.identity().string());
  append_u64(bytes, static_cast<std::uint64_t>(entries.size()));
  for (const auto& entry : entries) {
    append_u64(bytes, static_cast<std::uint64_t>(entry.id));
    append_string(bytes, entry.path);
    append_u64(bytes, entry.size);
    append_u16(bytes, static_cast<std::uint16_t>(entry.digest.size()));
    for (const auto byte : entry.digest)
      bytes.push_back(static_cast<std::byte>(byte));
  }
  return bytes;
}

std::string
stage_name(const application_attempt& attempt)
{
  const std::string text = attempt.identity().string();
  constexpr std::string_view prefix = "v1:sha256:";
  if (text.size() != prefix.size() + 64U ||
      text.compare(0, prefix.size(), prefix) != 0)
  {
    throw_error(payload_stage_error_code::binding_mismatch, 0,
                "application attempt has no supported storage identity");
  }
  return "payload-v1-sha256-" + text.substr(prefix.size());
}

std::string
entry_name(pkgimage::entry_id id)
{
  return "entry-" + std::to_string(static_cast<std::uint64_t>(id)) +
      ".payload";
}

std::string
pending_entry_name(pkgimage::entry_id id)
{
  return "entry-" + std::to_string(static_cast<std::uint64_t>(id)) +
      ".pending";
}

constexpr std::string_view binding_name = "binding-v1.bin";
constexpr std::string_view sealed_name = "sealed-v1.bin";
constexpr std::string_view sealed_pending_name = "sealed-v1.pending";
constexpr std::size_t maximum_binding_size = 16U * 1024U * 1024U;

bool
record_exists(int directory_fd, std::string_view name)
{
  struct stat status {};
  if (::fstatat(directory_fd, std::string(name).c_str(), &status,
                AT_SYMLINK_NOFOLLOW) == 0)
  {
    return true;
  }
  if (errno == ENOENT)
    return false;
  throw_error(payload_stage_error_code::binding_read_failed, errno,
              "cannot inspect private payload record");
}

void
write_record(int directory_fd,
             std::string_view name,
             const std::vector<std::byte>& bytes,
             bool exclusive)
{
  const int flags = O_WRONLY | O_CREAT | cloexec_flag() | nofollow_flag() |
      (exclusive ? O_EXCL : O_TRUNC);
  unique_fd file(open_at(
      directory_fd, std::string(name).c_str(), flags, 0600));
  if (file.get() < 0)
    throw_error(payload_stage_error_code::binding_write_failed, errno,
                "cannot create private payload record");
  set_close_on_exec(file.get(), payload_stage_error_code::binding_write_failed);
  write_all(file.get(), bytes);
  synchronize_fd(file.get(), payload_stage_error_code::stage_sync_failed,
                 "cannot synchronize private payload record");
}

void
validate_record(int directory_fd,
                std::string_view name,
                const std::vector<std::byte>& expected)
{
  const auto actual = read_file(
      directory_fd, std::string(name),
      payload_stage_error_code::binding_read_failed,
      payload_stage_error_code::binding_read_failed,
      maximum_binding_size);
  if (actual != expected)
    throw_error(payload_stage_error_code::binding_mismatch, 0,
                "private payload binding does not match this attempt");
}

application_backend_evidence_identity
evidence_identity(const std::vector<std::byte>& binding)
{
  const auto digest = sha256_bytes(binding.data(), binding.size());
  return application_backend_evidence_identity::parse(digest_text(digest));
}

const expected_payload*
find_expected(const std::vector<expected_payload>& entries,
              pkgimage::entry_id id) noexcept
{
  const auto item = std::lower_bound(
      entries.begin(), entries.end(), id,
      [](const auto& entry, const auto& wanted) { return entry.id < wanted; });
  return item != entries.end() && item->id == id ? &*item : nullptr;
}

std::size_t
expected_index(const std::vector<expected_payload>& entries,
               pkgimage::entry_id id)
{
  const auto item = std::lower_bound(
      entries.begin(), entries.end(), id,
      [](const auto& entry, const auto& wanted) { return entry.id < wanted; });
  if (item == entries.end() || item->id != id)
    throw_error(payload_stage_error_code::entry_unexpected, 0,
                "archive replay supplied an unselected payload entry");
  return static_cast<std::size_t>(item - entries.begin());
}

bool
same_entry(const pkgimage::package_entry& entry,
           const expected_payload& expected)
{
  return entry.id == expected.id &&
      entry.type == pkgimage::entry_type::regular &&
      entry.path.string() == expected.path && entry.size == expected.size &&
      entry.regular_content &&
      std::vector<std::uint8_t>(entry.regular_content->bytes().begin(),
                                entry.regular_content->bytes().end()) ==
          expected.digest;
}

void
rename_record(int directory_fd,
              const std::string& from,
              const std::string& to)
{
  for (;;) {
    if (::renameat(directory_fd, from.c_str(), directory_fd, to.c_str()) == 0)
      return;
    if (errno != EINTR)
      throw_error(payload_stage_error_code::stage_publish_failed, errno,
                  "cannot publish private payload record");
  }
}

struct stat
stable_stat(int fd)
{
  struct stat status {};
  if (::fstat(fd, &status) != 0)
    throw_error(payload_stage_error_code::entry_read_failed, errno,
                "cannot inspect staged payload");
  return status;
}

bool
same_regular(const struct stat& lhs, const struct stat& rhs) noexcept
{
  return S_ISREG(lhs.st_mode) && S_ISREG(rhs.st_mode) &&
      lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino &&
      lhs.st_size == rhs.st_size &&
      lhs.st_mtim.tv_sec == rhs.st_mtim.tv_sec &&
      lhs.st_mtim.tv_nsec == rhs.st_mtim.tv_nsec &&
      lhs.st_ctim.tv_sec == rhs.st_ctim.tv_sec &&
      lhs.st_ctim.tv_nsec == rhs.st_ctim.tv_nsec;
}

} // namespace

payload_stage_error::payload_stage_error(payload_stage_error_code code,
                                         int system_error,
                                         std::string message)
    : std::runtime_error(std::move(message)), code_(code),
      system_error_(system_error)
{
}

payload_stage_error_code
payload_stage_error::code() const noexcept
{
  return code_;
}

int
payload_stage_error::system_error() const noexcept
{
  return system_error_;
}

staged_regular_payload::staged_regular_payload(
    int descriptor, pkgimage::entry_id entry, std::uint64_t size) noexcept
    : descriptor_(descriptor), entry_(entry), size_(size)
{
}

staged_regular_payload::staged_regular_payload(
    staged_regular_payload&& other) noexcept
    : descriptor_(other.descriptor_), entry_(other.entry_), size_(other.size_)
{
  other.descriptor_ = -1;
}

staged_regular_payload&
staged_regular_payload::operator=(staged_regular_payload&& other) noexcept
{
  if (this != &other) {
    if (descriptor_ >= 0)
      static_cast<void>(::close(descriptor_));
    descriptor_ = other.descriptor_;
    entry_ = other.entry_;
    size_ = other.size_;
    other.descriptor_ = -1;
  }
  return *this;
}

staged_regular_payload::~staged_regular_payload()
{
  if (descriptor_ >= 0)
    static_cast<void>(::close(descriptor_));
}

int staged_regular_payload::descriptor() const noexcept { return descriptor_; }
pkgimage::entry_id staged_regular_payload::entry() const noexcept { return entry_; }
std::uint64_t staged_regular_payload::size() const noexcept { return size_; }

class sealed_application_payloads::implementation final {
public:
  implementation(int directory_fd,
                 application_attempt attempt,
                 pkgimage::package_image_identity image,
                 pkgimage::entry_selection selection,
                 std::vector<expected_payload> entries)
      : directory_fd(directory_fd), attempt(std::move(attempt)),
        image(std::move(image)), selection(std::move(selection)),
        entries(std::move(entries))
  {
  }

  ~implementation()
  {
    if (directory_fd >= 0)
      static_cast<void>(::close(directory_fd));
  }

  int directory_fd;
  application_attempt attempt;
  pkgimage::package_image_identity image;
  pkgimage::entry_selection selection;
  std::vector<expected_payload> entries;
};

sealed_application_payloads::sealed_application_payloads(
    std::unique_ptr<implementation> state)
    : state_(std::move(state))
{
}
sealed_application_payloads::sealed_application_payloads(
    sealed_application_payloads&&) noexcept = default;
sealed_application_payloads& sealed_application_payloads::operator=(
    sealed_application_payloads&&) noexcept = default;
sealed_application_payloads::~sealed_application_payloads() = default;

const application_attempt&
sealed_application_payloads::attempt() const noexcept
{
  return state_->attempt;
}

const application_attempt_nonce&
sealed_application_payloads::attempt_nonce() const noexcept
{
  return state_->attempt.nonce();
}

const pkgimage::package_image_identity&
sealed_application_payloads::image() const noexcept
{
  return state_->image;
}

const pkgimage::entry_selection&
sealed_application_payloads::selection() const noexcept
{
  return state_->selection;
}

staged_regular_payload
sealed_application_payloads::open(pkgimage::entry_id entry) const
{
  const expected_payload* expected = find_expected(state_->entries, entry);
  if (expected == nullptr)
    throw_error(payload_stage_error_code::entry_unexpected, 0,
                "requested payload entry is not in the sealed selection");

  unique_fd file(open_at(
      state_->directory_fd, entry_name(entry).c_str(),
      O_RDONLY | cloexec_flag() | nofollow_flag()));
  if (file.get() < 0)
    throw_error(payload_stage_error_code::entry_open_failed, errno,
                "cannot open sealed regular payload");
  set_close_on_exec(file.get(), payload_stage_error_code::entry_open_failed);

  const struct stat before = stable_stat(file.get());
  if (!S_ISREG(before.st_mode) || before.st_size < 0 ||
      static_cast<std::uint64_t>(before.st_size) != expected->size)
  {
    throw_error(payload_stage_error_code::entry_size_mismatch, 0,
                "sealed payload has another size or file type");
  }
  const auto digest = sha256_file(file.get());
  const struct stat after = stable_stat(file.get());
  if (!same_regular(before, after))
    throw_error(payload_stage_error_code::entry_content_mismatch, 0,
                "sealed payload changed while being verified");
  if (!std::equal(digest.begin(), digest.end(), expected->digest.begin(),
                  expected->digest.end()))
    throw_error(payload_stage_error_code::entry_content_mismatch, 0,
                "sealed payload has another content identity");
  if (::lseek(file.get(), 0, SEEK_SET) < 0)
    throw_error(payload_stage_error_code::entry_read_failed, errno,
                "cannot rewind sealed payload");
  return staged_regular_payload(file.release(), entry, expected->size);
}

class application_payload_stage::implementation final {
public:
  implementation(int root_fd,
                 int directory_fd,
                 int lock_fd,
                 std::string directory_name,
                 application_attempt attempt,
                 pkgimage::package_image_identity image,
                 pkgimage::entry_selection selection,
                 std::vector<expected_payload> entries,
                 std::vector<std::byte> binding,
                 bool verification)
      : root_fd(root_fd), directory_fd(directory_fd), lock_fd(lock_fd),
        directory_name(std::move(directory_name)), attempt(std::move(attempt)),
        image(std::move(image)), selection(std::move(selection)),
        entries(std::move(entries)), binding(std::move(binding)),
        completed(this->entries.size(), false), verification(verification),
        marker_visible(verification), evidence(evidence_identity(this->binding))
  {
  }

  ~implementation()
  {
    active_file.reset();
    if (lock_fd >= 0)
      static_cast<void>(::close(lock_fd));
    if (directory_fd >= 0)
      static_cast<void>(::close(directory_fd));
    if (root_fd >= 0)
      static_cast<void>(::close(root_fd));
  }

  int root_fd;
  int directory_fd;
  int lock_fd;
  std::string directory_name;
  application_attempt attempt;
  pkgimage::package_image_identity image;
  pkgimage::entry_selection selection;
  std::vector<expected_payload> entries;
  std::vector<std::byte> binding;
  std::vector<bool> completed;
  bool verification;
  bool sealed = false;
  bool marker_visible = false;
  bool abandoned = false;
  std::optional<std::size_t> active;
  unique_fd active_file;
  std::unique_ptr<EVP_MD_CTX, evp_context_deleter> digest;
  std::uint64_t written = 0;
  application_backend_evidence_identity evidence;
};

application_payload_stage::application_payload_stage(
    std::unique_ptr<implementation> state)
    : state_(std::move(state))
{
}

application_payload_stage::~application_payload_stage()
{
  abandon();
}

void
application_payload_stage::begin(const pkgimage::package_entry& entry)
{
  if (!state_ || state_->abandoned || state_->sealed)
    throw_error(payload_stage_error_code::entry_order_invalid, 0,
                "payload stage is not writable");
  if (state_->active)
    throw_error(payload_stage_error_code::entry_order_invalid, 0,
                "payload entry began before the prior entry ended");
  const std::size_t index = expected_index(state_->entries, entry.id);
  if (state_->completed[index])
    throw_error(payload_stage_error_code::entry_order_invalid, 0,
                "payload entry was replayed more than once");
  if (!same_entry(entry, state_->entries[index]))
    throw_error(payload_stage_error_code::entry_unexpected, 0,
                "archive replay entry differs from the bound package image");

  state_->active = index;
  state_->written = 0;
  if (state_->verification) {
    state_->active_file.reset(open_at(
        state_->directory_fd, entry_name(entry.id).c_str(),
        O_RDONLY | cloexec_flag() | nofollow_flag()));
    if (state_->active_file.get() < 0)
      throw_error(payload_stage_error_code::entry_open_failed, errno,
                  "cannot open sealed payload for replay verification");
  } else {
    state_->active_file.reset(open_at(
        state_->directory_fd, pending_entry_name(entry.id).c_str(),
        O_WRONLY | O_CREAT | O_TRUNC | cloexec_flag() | nofollow_flag(),
        0600));
    if (state_->active_file.get() < 0)
      throw_error(payload_stage_error_code::entry_open_failed, errno,
                  "cannot create pending private payload");
    state_->digest.reset(EVP_MD_CTX_new());
    if (!state_->digest ||
        EVP_DigestInit_ex(state_->digest.get(), EVP_sha256(), nullptr) != 1)
    {
      throw_error(payload_stage_error_code::entry_content_mismatch, 0,
                  "cannot initialize private payload digest");
    }
  }
  set_close_on_exec(
      state_->active_file.get(), payload_stage_error_code::entry_open_failed);
}

void
application_payload_stage::write(const pkgimage::package_entry& entry,
                                 const std::byte* data,
                                 std::size_t size)
{
  if (!state_ || !state_->active || state_->abandoned || state_->sealed)
    throw_error(payload_stage_error_code::entry_order_invalid, 0,
                "payload bytes arrived without an active entry");
  const expected_payload& expected = state_->entries[*state_->active];
  if (!same_entry(entry, expected))
    throw_error(payload_stage_error_code::entry_unexpected, 0,
                "payload bytes cite another package entry");
  if (size != 0 && data == nullptr)
    throw_error(payload_stage_error_code::entry_write_failed, EINVAL,
                "payload write supplied a null byte range");
  if (state_->written > expected.size ||
      size > expected.size - state_->written)
  {
    throw_error(payload_stage_error_code::entry_size_mismatch, 0,
                "payload replay exceeds the declared regular size");
  }

  if (state_->verification) {
    std::size_t offset = 0;
    std::array<std::byte, 64U * 1024U> buffer{};
    while (offset < size) {
      const std::size_t wanted = std::min(buffer.size(), size - offset);
      const ssize_t result = ::read(
          state_->active_file.get(), buffer.data(), wanted);
      if (result < 0) {
        if (errno == EINTR)
          continue;
        throw_error(payload_stage_error_code::entry_read_failed, errno,
                    "cannot verify sealed payload replay");
      }
      if (result == 0 ||
          std::memcmp(buffer.data(), data + offset,
                      static_cast<std::size_t>(result)) != 0)
      {
        throw_error(payload_stage_error_code::entry_content_mismatch, 0,
                    "archive replay differs from the sealed payload");
      }
      offset += static_cast<std::size_t>(result);
    }
  } else {
    write_all(state_->active_file.get(), data, size);
    if (size != 0 &&
        EVP_DigestUpdate(state_->digest.get(), data, size) != 1)
    {
      throw_error(payload_stage_error_code::entry_content_mismatch, 0,
                  "cannot update private payload digest");
    }
  }
  state_->written += static_cast<std::uint64_t>(size);
}

void
application_payload_stage::end(const pkgimage::package_entry& entry)
{
  if (!state_ || !state_->active || state_->abandoned || state_->sealed)
    throw_error(payload_stage_error_code::entry_order_invalid, 0,
                "payload entry ended without an active entry");
  const std::size_t index = *state_->active;
  const expected_payload& expected = state_->entries[index];
  if (!same_entry(entry, expected))
    throw_error(payload_stage_error_code::entry_unexpected, 0,
                "payload end cites another package entry");
  if (state_->written != expected.size)
    throw_error(payload_stage_error_code::entry_size_mismatch, 0,
                "payload replay has another regular size");

  if (state_->verification) {
    std::byte probe{};
    for (;;) {
      const ssize_t result = ::read(state_->active_file.get(), &probe, 1);
      if (result < 0 && errno == EINTR)
        continue;
      if (result < 0)
        throw_error(payload_stage_error_code::entry_read_failed, errno,
                    "cannot finish verifying sealed payload");
      if (result != 0)
        throw_error(payload_stage_error_code::entry_size_mismatch, 0,
                    "sealed payload contains bytes beyond archive replay");
      break;
    }
    state_->active_file.reset();
  } else {
    std::array<std::uint8_t, 32> digest{};
    unsigned int digest_size = 0;
    if (EVP_DigestFinal_ex(
            state_->digest.get(), digest.data(), &digest_size) != 1 ||
        digest_size != digest.size())
    {
      throw_error(payload_stage_error_code::entry_content_mismatch, 0,
                  "cannot finalize private payload digest");
    }
    state_->digest.reset();
    if (!std::equal(digest.begin(), digest.end(), expected.digest.begin(),
                    expected.digest.end()))
      throw_error(payload_stage_error_code::entry_content_mismatch, 0,
                  "payload replay has another regular content identity");
    synchronize_fd(
        state_->active_file.get(), payload_stage_error_code::entry_sync_failed,
        "cannot synchronize private payload");
    state_->active_file.reset();
    rename_record(
        state_->directory_fd, pending_entry_name(entry.id), entry_name(entry.id));
    synchronize_fd(
        state_->directory_fd, payload_stage_error_code::stage_sync_failed,
        "cannot synchronize private payload directory");
  }
  state_->completed[index] = true;
  state_->active.reset();
  state_->written = 0;
}

backend_operation_result
application_payload_stage::seal()
{
  if (!state_ || state_->abandoned)
    return backend_operation_result(backend_operation_outcome::failed);
  if (state_->sealed)
    return backend_operation_result(
        backend_operation_outcome::completed, {state_->evidence});
  if (state_->active ||
      std::find(state_->completed.begin(), state_->completed.end(), false) !=
          state_->completed.end())
  {
    return backend_operation_result(
        backend_operation_outcome::failed, {state_->evidence});
  }

  try {
    if (record_exists(state_->directory_fd, sealed_name)) {
      validate_record(state_->directory_fd, sealed_name, state_->binding);
      state_->marker_visible = true;
    } else {
      write_record(
          state_->directory_fd, sealed_pending_name, state_->binding, false);
      rename_record(
          state_->directory_fd, std::string(sealed_pending_name),
          std::string(sealed_name));
      state_->marker_visible = true;
    }
    synchronize_fd(
        state_->directory_fd, payload_stage_error_code::stage_sync_failed,
        "cannot synchronize sealed payload stage");
    state_->sealed = true;
    return backend_operation_result(
        backend_operation_outcome::completed, {state_->evidence});
  } catch (const payload_stage_error&) {
    return backend_operation_result(
        state_->marker_visible ? backend_operation_outcome::indeterminate
                               : backend_operation_outcome::failed,
        {state_->evidence});
  }
}

void
application_payload_stage::abandon() noexcept
{
  if (!state_ || state_->abandoned || state_->sealed || state_->marker_visible)
    return;
  state_->abandoned = true;
  state_->active_file.reset();
  state_->digest.reset();
  for (const auto& entry : state_->entries) {
    static_cast<void>(::unlinkat(
        state_->directory_fd, pending_entry_name(entry.id).c_str(), 0));
    static_cast<void>(::unlinkat(
        state_->directory_fd, entry_name(entry.id).c_str(), 0));
  }
  static_cast<void>(::unlinkat(
      state_->directory_fd, std::string(sealed_pending_name).c_str(), 0));
  static_cast<void>(::unlinkat(
      state_->directory_fd, std::string(binding_name).c_str(), 0));
  if (state_->lock_fd >= 0) {
    static_cast<void>(::close(state_->lock_fd));
    state_->lock_fd = -1;
  }
  static_cast<void>(::unlinkat(state_->directory_fd, "lock-v1", 0));
  const int directory_fd = state_->directory_fd;
  state_->directory_fd = -1;
  if (directory_fd >= 0)
    static_cast<void>(::close(directory_fd));
  static_cast<void>(::unlinkat(
      state_->root_fd, state_->directory_name.c_str(), AT_REMOVEDIR));
  static_cast<void>(::fsync(state_->root_fd));
}

bool
application_payload_stage::sealed() const noexcept
{
  return state_ && state_->sealed;
}

application_payload_store::application_payload_store(int directory_fd) noexcept
    : directory_fd_(directory_fd)
{
}

application_payload_store
application_payload_store::open(const std::string& directory)
{
  unique_fd descriptor(open_path(
      directory.c_str(), O_RDONLY | O_DIRECTORY | cloexec_flag() |
          nofollow_flag()));
  if (descriptor.get() < 0)
    throw_error(payload_stage_error_code::directory_open_failed, errno,
                "cannot open payload staging directory");
  set_close_on_exec(
      descriptor.get(), payload_stage_error_code::directory_open_failed);
  require_directory(
      descriptor.get(), payload_stage_error_code::directory_invalid,
      "payload staging directory");
  return application_payload_store(descriptor.release());
}

application_payload_store
application_payload_store::from_directory_fd(int directory_fd)
{
  unique_fd descriptor(duplicate_fd(
      directory_fd, payload_stage_error_code::directory_open_failed));
  require_directory(
      descriptor.get(), payload_stage_error_code::directory_invalid,
      "payload staging descriptor");
  return application_payload_store(descriptor.release());
}

application_payload_store::application_payload_store(
    application_payload_store&& other) noexcept
    : directory_fd_(other.directory_fd_)
{
  other.directory_fd_ = -1;
}

application_payload_store&
application_payload_store::operator=(application_payload_store&& other) noexcept
{
  if (this != &other) {
    if (directory_fd_ >= 0)
      static_cast<void>(::close(directory_fd_));
    directory_fd_ = other.directory_fd_;
    other.directory_fd_ = -1;
  }
  return *this;
}

application_payload_store::~application_payload_store()
{
  if (directory_fd_ >= 0)
    static_cast<void>(::close(directory_fd_));
}

std::unique_ptr<application_payload_stage>
application_payload_store::begin(
    const application_attempt& attempt,
    const pkgimage::package_image& image,
    const pkgimage::entry_selection& selection) const
{
  auto entries = expected_payloads(image, selection);
  auto binding = binding_encoding(attempt, image, entries);
  const std::string name = stage_name(attempt);

  bool created = false;
  if (::mkdirat(directory_fd_, name.c_str(), 0700) == 0) {
    created = true;
  } else if (errno != EEXIST) {
    throw_error(payload_stage_error_code::stage_open_failed, errno,
                "cannot create private payload stage");
  }

  unique_fd stage;
  try {
    stage.reset(open_at(
        directory_fd_, name.c_str(),
        O_RDONLY | O_DIRECTORY | cloexec_flag() | nofollow_flag()));
    if (stage.get() < 0)
      throw_error(payload_stage_error_code::stage_open_failed, errno,
                  "cannot open private payload stage");
    set_close_on_exec(stage.get(), payload_stage_error_code::stage_open_failed);
    require_directory(
        stage.get(), payload_stage_error_code::stage_invalid,
        "private payload stage");
    unique_fd stage_lock(lock_stage(stage.get(), F_WRLCK, true));

    if (record_exists(stage.get(), binding_name)) {
      validate_record(stage.get(), binding_name, binding);
    } else {
      if (!created)
        throw_error(payload_stage_error_code::stage_invalid, 0,
                    "existing private payload stage lacks its binding record");
      write_record(stage.get(), binding_name, binding, true);
      synchronize_fd(
          stage.get(), payload_stage_error_code::stage_sync_failed,
          "cannot synchronize payload-stage binding");
    }
    if (created)
      synchronize_fd(
          directory_fd_, payload_stage_error_code::stage_sync_failed,
          "cannot synchronize payload staging namespace");

    bool verification = false;
    if (record_exists(stage.get(), sealed_name)) {
      validate_record(stage.get(), sealed_name, binding);
      verification = true;
    }

    auto state = std::make_unique<application_payload_stage::implementation>(
        duplicate_fd(
            directory_fd_, payload_stage_error_code::stage_open_failed),
        stage.release(), stage_lock.release(), name, attempt, image.identity(),
        selection, std::move(entries), std::move(binding), verification);
    return std::unique_ptr<application_payload_stage>(
        new application_payload_stage(std::move(state)));
  } catch (...) {
    if (created) {
      if (stage.get() >= 0) {
        static_cast<void>(::unlinkat(
            stage.get(), std::string(sealed_pending_name).c_str(), 0));
        static_cast<void>(::unlinkat(
            stage.get(), std::string(sealed_name).c_str(), 0));
        static_cast<void>(::unlinkat(
            stage.get(), std::string(binding_name).c_str(), 0));
        static_cast<void>(::unlinkat(stage.get(), "lock-v1", 0));
      }
      stage.reset();
      static_cast<void>(::unlinkat(directory_fd_, name.c_str(), AT_REMOVEDIR));
      static_cast<void>(::fsync(directory_fd_));
    }
    throw;
  }
}

std::optional<sealed_application_payloads>
application_payload_store::load(
    const application_attempt& attempt,
    const pkgimage::package_image& image,
    const pkgimage::entry_selection& selection) const
{
  auto entries = expected_payloads(image, selection);
  const auto binding = binding_encoding(attempt, image, entries);
  const std::string name = stage_name(attempt);
  unique_fd stage(open_at(
      directory_fd_, name.c_str(),
      O_RDONLY | O_DIRECTORY | cloexec_flag() | nofollow_flag()));
  if (stage.get() < 0) {
    if (errno == ENOENT)
      return std::nullopt;
    throw_error(payload_stage_error_code::stage_open_failed, errno,
                "cannot open sealed payload stage");
  }
  set_close_on_exec(stage.get(), payload_stage_error_code::stage_open_failed);
  require_directory(
      stage.get(), payload_stage_error_code::stage_invalid,
      "sealed payload stage");
  validate_record(stage.get(), binding_name, binding);
  if (!record_exists(stage.get(), sealed_name))
    return std::nullopt;
  validate_record(stage.get(), sealed_name, binding);

  auto state = std::make_unique<sealed_application_payloads::implementation>(
      stage.release(), attempt, image.identity(), selection, std::move(entries));
  return sealed_application_payloads(std::move(state));
}

void
application_payload_store::synchronize() const
{
  synchronize_fd(
      directory_fd_, payload_stage_error_code::stage_sync_failed,
      "cannot synchronize payload staging namespace");
}

} // namespace pkgapply::posix
