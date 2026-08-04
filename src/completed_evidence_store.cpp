// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/completed_evidence_store.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

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
    const int value = value_;
    value_ = -1;
    return value;
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

std::atomic<std::uint64_t> temporary_sequence{0};

[[noreturn]] void throw_system(
    completed_evidence_store_error_code code,
    std::string_view operation,
    int error = errno,
    bool publication_visible = false)
{
  throw completed_evidence_store_error(
      code, error, std::string(operation) + ": " + std::strerror(error),
      publication_visible);
}

int open_path(const char* path, int flags)
{
  for (;;) {
    const int result = ::open(path, flags);
    if (result >= 0 || errno != EINTR)
      return result;
  }
}

int open_at(int directory_fd, const char* path, int flags, mode_t mode = 0)
{
  for (;;) {
    const int result = mode == 0
        ? ::openat(directory_fd, path, flags)
        : ::openat(directory_fd, path, flags, mode);
    if (result >= 0 || errno != EINTR)
      return result;
  }
}

int nofollow_flag() noexcept
{
#ifdef O_NOFOLLOW
  return O_NOFOLLOW;
#else
  return 0;
#endif
}

int cloexec_flag() noexcept
{
#ifdef O_CLOEXEC
  return O_CLOEXEC;
#else
  return 0;
#endif
}

void set_close_on_exec(int fd)
{
#ifndef O_CLOEXEC
  const int flags = ::fcntl(fd, F_GETFD);
  if (flags < 0 || ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
    throw_system(
        completed_evidence_store_error_code::directory_open_failed,
        "cannot set close-on-exec on completed-evidence descriptor");
#else
  static_cast<void>(fd);
#endif
}

void require_directory(int fd)
{
  struct stat status {};
  if (::fstat(fd, &status) != 0)
    throw_system(
        completed_evidence_store_error_code::directory_invalid,
        "cannot inspect completed-evidence directory");
  if (!S_ISDIR(status.st_mode))
    throw completed_evidence_store_error(
        completed_evidence_store_error_code::directory_invalid, 0,
        "completed-evidence descriptor does not name a directory");
}

void synchronize_fd(
    int fd,
    completed_evidence_store_error_code code,
    std::string_view operation,
    bool publication_visible = false)
{
  for (;;) {
    if (::fsync(fd) == 0)
      return;
    if (errno != EINTR)
      throw_system(code, operation, errno, publication_visible);
  }
}

std::string storage_name(
    const completed_application_evidence_identity& identity)
{
  const auto& text = identity.string();
  constexpr std::string_view prefix = "v1:sha256:";
  if (text.size() != prefix.size() + 64 ||
      text.compare(0, prefix.size(), prefix) != 0)
  {
    throw completed_evidence_store_error(
        completed_evidence_store_error_code::record_invalid, 0,
        "completed-evidence identity has no supported storage form");
  }
  return "completed-v1-sha256-" + text.substr(prefix.size()) + ".bin";
}

std::optional<completed_application_evidence_encoding> read_encoding(
    int directory_fd,
    const std::string& name)
{
  unique_fd file(open_at(
      directory_fd, name.c_str(),
      O_RDONLY | cloexec_flag() | nofollow_flag()));
  if (file.get() < 0) {
    if (errno == ENOENT)
      return std::nullopt;
    throw_system(
        completed_evidence_store_error_code::record_open_failed,
        "cannot open completed-evidence record");
  }
  set_close_on_exec(file.get());

  struct stat status {};
  if (::fstat(file.get(), &status) != 0)
    throw_system(
        completed_evidence_store_error_code::record_read_failed,
        "cannot inspect completed-evidence record");
  if (!S_ISREG(status.st_mode) || (status.st_mode & 0777) != 0600)
    throw completed_evidence_store_error(
        completed_evidence_store_error_code::record_invalid, 0,
        "completed-evidence record is not a private regular file");
  if (status.st_size < 0 ||
      static_cast<std::uint64_t>(status.st_size) >
          maximum_completed_application_evidence_encoding_size)
  {
    throw completed_evidence_store_error(
        completed_evidence_store_error_code::record_invalid, 0,
        "completed-evidence record exceeds the encoding size limit");
  }

  completed_application_evidence_encoding bytes(
      static_cast<std::size_t>(status.st_size));
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto result = ::read(
        file.get(), bytes.data() + offset, bytes.size() - offset);
    if (result < 0) {
      if (errno == EINTR)
        continue;
      throw_system(
          completed_evidence_store_error_code::record_read_failed,
          "cannot read completed-evidence record");
    }
    if (result == 0)
      throw completed_evidence_store_error(
          completed_evidence_store_error_code::record_invalid, 0,
          "completed-evidence record was truncated while reading");
    offset += static_cast<std::size_t>(result);
  }

  std::uint8_t probe = 0;
  for (;;) {
    const auto result = ::read(file.get(), &probe, 1);
    if (result < 0 && errno == EINTR)
      continue;
    if (result < 0)
      throw_system(
          completed_evidence_store_error_code::record_read_failed,
          "cannot finish reading completed-evidence record");
    if (result != 0)
      throw completed_evidence_store_error(
          completed_evidence_store_error_code::record_invalid, 0,
          "completed-evidence record changed size while reading");
    break;
  }
  return bytes;
}

void write_all(
    int fd,
    const completed_application_evidence_encoding& bytes)
{
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto result = ::write(
        fd, bytes.data() + offset, bytes.size() - offset);
    if (result < 0) {
      if (errno == EINTR)
        continue;
      throw_system(
          completed_evidence_store_error_code::record_write_failed,
          "cannot write completed-evidence record");
    }
    if (result == 0)
      throw completed_evidence_store_error(
          completed_evidence_store_error_code::record_write_failed, 0,
          "completed-evidence write made no progress");
    offset += static_cast<std::size_t>(result);
  }
}

std::string temporary_name(const std::string& final_name)
{
  const auto sequence = temporary_sequence.fetch_add(
      1, std::memory_order_relaxed);
  return final_name + ".tmp." +
         std::to_string(static_cast<long long>(::getpid())) + "." +
         std::to_string(sequence);
}

bool link_without_replace(
    int directory_fd,
    const std::string& temporary,
    const std::string& final_name)
{
  for (;;) {
    if (::linkat(
            directory_fd, temporary.c_str(), directory_fd,
            final_name.c_str(), 0) == 0)
      return true;
    if (errno == EEXIST)
      return false;
    if (errno != EINTR)
      throw_system(
          completed_evidence_store_error_code::record_publish_failed,
          "cannot publish immutable completed-evidence record");
  }
}

void unlink_temporary(
    int directory_fd,
    const std::string& temporary,
    bool visible)
{
  for (;;) {
    if (::unlinkat(directory_fd, temporary.c_str(), 0) == 0)
      return;
    if (errno != EINTR)
      throw_system(
          completed_evidence_store_error_code::record_publish_failed,
          "cannot remove temporary completed-evidence record", errno,
          visible);
  }
}

bool publish_encoding(
    int directory_fd,
    const std::string& final_name,
    const completed_application_evidence_encoding& bytes)
{
  std::string temporary;
  unique_fd file;
  for (int attempt = 0; attempt < 128; ++attempt) {
    temporary = temporary_name(final_name);
    file.reset(open_at(
        directory_fd, temporary.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | cloexec_flag() | nofollow_flag(),
        0600));
    if (file.get() >= 0)
      break;
    if (errno != EEXIST)
      throw_system(
          completed_evidence_store_error_code::record_open_failed,
          "cannot create temporary completed-evidence record");
  }
  if (file.get() < 0)
    throw completed_evidence_store_error(
        completed_evidence_store_error_code::record_open_failed, EEXIST,
        "cannot allocate a unique completed-evidence temporary file");
  set_close_on_exec(file.get());
  if (::fchmod(file.get(), 0600) != 0)
    throw_system(
        completed_evidence_store_error_code::record_write_failed,
        "cannot set completed-evidence record mode");

  bool visible = false;
  try {
    write_all(file.get(), bytes);
    synchronize_fd(
        file.get(), completed_evidence_store_error_code::record_sync_failed,
        "cannot synchronize completed-evidence record");
    file.reset();
    visible = link_without_replace(
        directory_fd, temporary, final_name);
    unlink_temporary(directory_fd, temporary, visible);
    temporary.clear();
  }
  catch (...) {
    if (!temporary.empty())
      static_cast<void>(::unlinkat(directory_fd, temporary.c_str(), 0));
    throw;
  }
  return visible;
}

template<class Request>
completed_application_evidence decode_stored(
    const completed_application_evidence_encoding& encoding,
    const completed_application_evidence_identity& expected,
    const Request& request)
{
  try {
    auto evidence = decode_completed_application_evidence(
        encoding, request);
    if (evidence.identity() != expected)
      throw completed_evidence_store_error(
          completed_evidence_store_error_code::record_invalid, 0,
          "completed-evidence filename and content disagree");
    return evidence;
  }
  catch (const completed_evidence_store_error&) {
    throw;
  }
  catch (const completed_application_evidence_codec_error& error) {
    throw completed_evidence_store_error(
        completed_evidence_store_error_code::record_invalid, 0,
        std::string("completed-evidence record is invalid: ") + error.what());
  }
}

template<class Request>
std::optional<completed_application_evidence> load_evidence(
    int directory_fd,
    const completed_application_evidence_identity& identity,
    const Request& request)
{
  const auto encoding = read_encoding(
      directory_fd, storage_name(identity));
  if (!encoding)
    return std::nullopt;
  return decode_stored(*encoding, identity, request);
}

} // namespace

completed_evidence_store_error::completed_evidence_store_error(
    completed_evidence_store_error_code code,
    int system_error,
    std::string message,
    bool publication_visible)
    : std::runtime_error(std::move(message)), code_(code),
      system_error_(system_error), publication_visible_(publication_visible)
{
}

completed_evidence_store_error_code
completed_evidence_store_error::code() const noexcept
{
  return code_;
}

int completed_evidence_store_error::system_error() const noexcept
{
  return system_error_;
}

bool completed_evidence_store_error::publication_visible() const noexcept
{
  return publication_visible_;
}

completed_application_evidence_store
completed_application_evidence_store::open(const std::string& directory)
{
  if (directory.empty())
    throw completed_evidence_store_error(
        completed_evidence_store_error_code::directory_open_failed, EINVAL,
        "completed-evidence directory path is empty");
  int flags = O_RDONLY | cloexec_flag() | nofollow_flag();
#ifdef O_DIRECTORY
  flags |= O_DIRECTORY;
#endif
  unique_fd fd(open_path(directory.c_str(), flags));
  if (fd.get() < 0)
    throw_system(
        completed_evidence_store_error_code::directory_open_failed,
        "cannot open completed-evidence directory");
  set_close_on_exec(fd.get());
  require_directory(fd.get());
  return completed_application_evidence_store(fd.release());
}

completed_application_evidence_store
completed_application_evidence_store::from_directory_fd(int directory_fd)
{
  if (directory_fd < 0)
    throw completed_evidence_store_error(
        completed_evidence_store_error_code::directory_invalid, EBADF,
        "completed-evidence directory descriptor is invalid");
#ifdef F_DUPFD_CLOEXEC
  unique_fd duplicate(::fcntl(directory_fd, F_DUPFD_CLOEXEC, 0));
#else
  unique_fd duplicate(::dup(directory_fd));
#endif
  if (duplicate.get() < 0)
    throw_system(
        completed_evidence_store_error_code::directory_open_failed,
        "cannot duplicate completed-evidence directory descriptor");
  set_close_on_exec(duplicate.get());
  require_directory(duplicate.get());
  return completed_application_evidence_store(duplicate.release());
}

completed_application_evidence_store::completed_application_evidence_store(
    int directory_fd) noexcept
    : directory_fd_(directory_fd)
{
}

completed_application_evidence_store::completed_application_evidence_store(
    completed_application_evidence_store&& other) noexcept
    : directory_fd_(other.directory_fd_)
{
  other.directory_fd_ = -1;
}

completed_application_evidence_store&
completed_application_evidence_store::operator=(
    completed_application_evidence_store&& other) noexcept
{
  if (this != &other) {
    if (directory_fd_ >= 0)
      static_cast<void>(::close(directory_fd_));
    directory_fd_ = other.directory_fd_;
    other.directory_fd_ = -1;
  }
  return *this;
}

completed_application_evidence_store::~completed_application_evidence_store()
{
  if (directory_fd_ >= 0)
    static_cast<void>(::close(directory_fd_));
}

template<class Request>
completed_application_evidence_identity publish_evidence(
    int directory_fd,
    const completed_application_evidence& evidence,
    const Request& request)
{
  const auto name = storage_name(evidence.identity());
  const auto encoding = encode_completed_application_evidence(evidence);
  static_cast<void>(decode_stored(
      encoding, evidence.identity(), request));
  if (const auto current = read_encoding(directory_fd, name)) {
    static_cast<void>(decode_stored(*current, evidence.identity(), request));
    if (*current != encoding)
      throw completed_evidence_store_error(
          completed_evidence_store_error_code::record_conflict, EEXIST,
          "completed-evidence identity names different durable bytes", true);
    return evidence.identity();
  }

  if (!publish_encoding(directory_fd, name, encoding)) {
    const auto current = read_encoding(directory_fd, name);
    if (!current)
      throw completed_evidence_store_error(
          completed_evidence_store_error_code::record_conflict, EEXIST,
          "completed-evidence publication raced with a missing record", true);
    static_cast<void>(decode_stored(
        *current, evidence.identity(), request));
    if (*current != encoding)
      throw completed_evidence_store_error(
          completed_evidence_store_error_code::record_conflict, EEXIST,
          "completed-evidence identity was published with different bytes",
          true);
  }
  return evidence.identity();
}

completed_application_evidence_identity
completed_application_evidence_store::publish(
    const completed_application_evidence& evidence,
    const installation_application_request& request) const
{
  return publish_evidence(directory_fd_, evidence, request);
}

completed_application_evidence_identity
completed_application_evidence_store::publish(
    const completed_application_evidence& evidence,
    const upgrade_application_request& request) const
{
  return publish_evidence(directory_fd_, evidence, request);
}

completed_application_evidence_identity
completed_application_evidence_store::publish(
    const completed_application_evidence& evidence,
    const removal_application_request& request) const
{
  return publish_evidence(directory_fd_, evidence, request);
}

std::optional<completed_application_evidence>
completed_application_evidence_store::load(
    const completed_application_evidence_identity& identity,
    const installation_application_request& request) const
{
  return load_evidence(directory_fd_, identity, request);
}

std::optional<completed_application_evidence>
completed_application_evidence_store::load(
    const completed_application_evidence_identity& identity,
    const upgrade_application_request& request) const
{
  return load_evidence(directory_fd_, identity, request);
}

std::optional<completed_application_evidence>
completed_application_evidence_store::load(
    const completed_application_evidence_identity& identity,
    const removal_application_request& request) const
{
  return load_evidence(directory_fd_, identity, request);
}

void completed_application_evidence_store::synchronize() const
{
  synchronize_fd(
      directory_fd_,
      completed_evidence_store_error_code::namespace_sync_failed,
      "cannot synchronize completed-evidence namespace", true);
}

} // namespace pkgapply::posix
