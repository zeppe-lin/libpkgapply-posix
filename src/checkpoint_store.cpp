// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/checkpoint_store.h>

#include <algorithm>
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
    checkpoint_store_error_code code,
    std::string_view operation,
    int error = errno,
    bool publication_visible = false)
{
  throw checkpoint_store_error(
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

void synchronize_fd(
    int fd,
    checkpoint_store_error_code code,
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
        checkpoint_store_error_code::directory_open_failed,
        "cannot set close-on-exec on checkpoint-store descriptor");
#else
  static_cast<void>(fd);
#endif
}

void require_directory(int fd)
{
  struct stat status {};
  if (::fstat(fd, &status) != 0)
    throw_system(
        checkpoint_store_error_code::directory_invalid,
        "cannot inspect checkpoint-store directory");
  if (!S_ISDIR(status.st_mode))
    throw checkpoint_store_error(
        checkpoint_store_error_code::directory_invalid, 0,
        "checkpoint-store descriptor does not name a directory");
}

std::string storage_name(const application_journal_record_identity& identity)
{
  const auto& text = identity.string();
  constexpr std::string_view prefix = "v1:sha256:";
  if (text.size() != prefix.size() + 64 ||
      text.compare(0, prefix.size(), prefix) != 0)
  {
    throw checkpoint_store_error(
        checkpoint_store_error_code::snapshot_corrupt, 0,
        "journal-record identity has no supported storage representation");
  }
  return "checkpoint-v1-sha256-" + text.substr(prefix.size()) + ".bin";
}

std::optional<application_restart_checkpoint_encoding> read_encoding(
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
        checkpoint_store_error_code::snapshot_open_failed,
        "cannot open restart checkpoint");
  }
  set_close_on_exec(file.get());

  struct stat status {};
  if (::fstat(file.get(), &status) != 0)
    throw_system(
        checkpoint_store_error_code::snapshot_read_failed,
        "cannot inspect restart checkpoint");
  if (!S_ISREG(status.st_mode))
    throw checkpoint_store_error(
        checkpoint_store_error_code::snapshot_corrupt, 0,
        "restart checkpoint is not a regular file");
  if (status.st_size < 0 ||
      static_cast<std::uint64_t>(status.st_size) >
          maximum_application_restart_checkpoint_encoding_size)
  {
    throw checkpoint_store_error(
        checkpoint_store_error_code::snapshot_corrupt, 0,
        "restart checkpoint exceeds the encoding size limit");
  }

  application_restart_checkpoint_encoding bytes(
      static_cast<std::size_t>(status.st_size));
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto result = ::read(
        file.get(), bytes.data() + offset, bytes.size() - offset);
    if (result < 0) {
      if (errno == EINTR)
        continue;
      throw_system(
          checkpoint_store_error_code::snapshot_read_failed,
          "cannot read restart checkpoint");
    }
    if (result == 0)
      throw checkpoint_store_error(
          checkpoint_store_error_code::snapshot_corrupt, 0,
          "restart checkpoint was truncated while reading");
    offset += static_cast<std::size_t>(result);
  }

  std::uint8_t probe = 0;
  for (;;) {
    const auto result = ::read(file.get(), &probe, 1);
    if (result < 0 && errno == EINTR)
      continue;
    if (result < 0)
      throw_system(
          checkpoint_store_error_code::snapshot_read_failed,
          "cannot finish reading restart checkpoint");
    if (result != 0)
      throw checkpoint_store_error(
          checkpoint_store_error_code::snapshot_corrupt, 0,
          "restart checkpoint changed size while reading");
    break;
  }
  return bytes;
}

void write_all(int fd, const application_restart_checkpoint_encoding& bytes)
{
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto result = ::write(fd, bytes.data() + offset, bytes.size() - offset);
    if (result < 0) {
      if (errno == EINTR)
        continue;
      throw_system(
          checkpoint_store_error_code::snapshot_write_failed,
          "cannot write restart checkpoint");
    }
    if (result == 0)
      throw checkpoint_store_error(
          checkpoint_store_error_code::snapshot_write_failed, 0,
          "restart checkpoint write made no progress");
    offset += static_cast<std::size_t>(result);
  }
}

std::string temporary_name(const std::string& final_name)
{
  const auto sequence = temporary_sequence.fetch_add(1, std::memory_order_relaxed);
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
          checkpoint_store_error_code::snapshot_publish_failed,
          "cannot publish immutable restart checkpoint");
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
          checkpoint_store_error_code::snapshot_publish_failed,
          "cannot remove temporary restart checkpoint", errno, visible);
  }
}

void publish_encoding(
    int directory_fd,
    const std::string& final_name,
    const application_restart_checkpoint_encoding& bytes)
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
          checkpoint_store_error_code::snapshot_open_failed,
          "cannot create temporary restart checkpoint");
  }
  if (file.get() < 0)
    throw checkpoint_store_error(
        checkpoint_store_error_code::snapshot_open_failed, EEXIST,
        "cannot allocate a unique temporary restart checkpoint");
  set_close_on_exec(file.get());

  bool visible = false;
  try {
    write_all(file.get(), bytes);
    synchronize_fd(
        file.get(), checkpoint_store_error_code::snapshot_sync_failed,
        "cannot synchronize temporary restart checkpoint");
    file.reset();
    visible = link_without_replace(directory_fd, temporary, final_name);
    unlink_temporary(directory_fd, temporary, visible);
    temporary.clear();
    if (visible) {
      synchronize_fd(
          directory_fd, checkpoint_store_error_code::directory_sync_failed,
          "cannot synchronize checkpoint-store directory", true);
    }
  }
  catch (...) {
    if (!temporary.empty())
      static_cast<void>(::unlinkat(directory_fd, temporary.c_str(), 0));
    throw;
  }
  if (!visible)
    throw checkpoint_store_error(
        checkpoint_store_error_code::snapshot_conflict, EEXIST,
        "restart checkpoint already exists with another durable encoding");
}

template<class Request>
application_restart_checkpoint decode_stored(
    const application_restart_checkpoint_encoding& encoding,
    const application_journal_record& expected,
    const Request& request)
{
  try {
    auto checkpoint = decode_application_restart_checkpoint(
        encoding, expected, request);
    if (checkpoint.journal() != expected.identity())
      throw checkpoint_store_error(
          checkpoint_store_error_code::snapshot_corrupt, 0,
          "restart checkpoint filename and content disagree");
    return checkpoint;
  }
  catch (const checkpoint_store_error&) {
    throw;
  }
  catch (const application_restart_checkpoint_codec_error& error) {
    throw checkpoint_store_error(
        checkpoint_store_error_code::snapshot_corrupt, 0,
        std::string("restart checkpoint is corrupt: ") + error.what());
  }
}

} // namespace

checkpoint_store_error::checkpoint_store_error(
    checkpoint_store_error_code code,
    int system_error,
    std::string message,
    bool publication_visible)
    : std::runtime_error(std::move(message)), code_(code),
      system_error_(system_error), publication_visible_(publication_visible)
{
}

checkpoint_store_error_code checkpoint_store_error::code() const noexcept
{
  return code_;
}

int checkpoint_store_error::system_error() const noexcept
{
  return system_error_;
}

bool checkpoint_store_error::publication_visible() const noexcept
{
  return publication_visible_;
}

application_restart_checkpoint_store
application_restart_checkpoint_store::open(const std::string& directory)
{
  if (directory.empty())
    throw checkpoint_store_error(
        checkpoint_store_error_code::directory_open_failed, EINVAL,
        "checkpoint-store directory path is empty");
  int flags = O_RDONLY | cloexec_flag() | nofollow_flag();
#ifdef O_DIRECTORY
  flags |= O_DIRECTORY;
#endif
  unique_fd fd(open_path(directory.c_str(), flags));
  if (fd.get() < 0)
    throw_system(
        checkpoint_store_error_code::directory_open_failed,
        "cannot open checkpoint-store directory");
  set_close_on_exec(fd.get());
  require_directory(fd.get());
  return application_restart_checkpoint_store(fd.release());
}

application_restart_checkpoint_store
application_restart_checkpoint_store::from_directory_fd(int directory_fd)
{
  if (directory_fd < 0)
    throw checkpoint_store_error(
        checkpoint_store_error_code::directory_invalid, EBADF,
        "checkpoint-store directory descriptor is invalid");
#ifdef F_DUPFD_CLOEXEC
  unique_fd duplicate(::fcntl(directory_fd, F_DUPFD_CLOEXEC, 0));
#else
  unique_fd duplicate(::dup(directory_fd));
#endif
  if (duplicate.get() < 0)
    throw_system(
        checkpoint_store_error_code::directory_open_failed,
        "cannot duplicate checkpoint-store directory descriptor");
  set_close_on_exec(duplicate.get());
  require_directory(duplicate.get());
  return application_restart_checkpoint_store(duplicate.release());
}

application_restart_checkpoint_store::application_restart_checkpoint_store(
    int directory_fd) noexcept
    : directory_fd_(directory_fd)
{
}

application_restart_checkpoint_store::application_restart_checkpoint_store(
    application_restart_checkpoint_store&& other) noexcept
    : directory_fd_(other.directory_fd_)
{
  other.directory_fd_ = -1;
}

application_restart_checkpoint_store&
application_restart_checkpoint_store::operator=(
    application_restart_checkpoint_store&& other) noexcept
{
  if (this != &other) {
    if (directory_fd_ >= 0)
      static_cast<void>(::close(directory_fd_));
    directory_fd_ = other.directory_fd_;
    other.directory_fd_ = -1;
  }
  return *this;
}

application_restart_checkpoint_store::~application_restart_checkpoint_store()
{
  if (directory_fd_ >= 0)
    static_cast<void>(::close(directory_fd_));
}

application_restart_checkpoint application_restart_checkpoint_store::publish(
    const application_journal_record& journal,
    const application_restart_checkpoint& checkpoint)
{
  if (checkpoint.journal() != journal.identity())
    throw checkpoint_store_error(
        checkpoint_store_error_code::snapshot_conflict, 0,
        "restart checkpoint does not belong to the supplied journal snapshot");
  const auto name = storage_name(journal.identity());
  const auto encoding = encode_application_restart_checkpoint(checkpoint);
  if (const auto current = read_encoding(directory_fd_, name)) {
    if (*current != encoding)
      throw checkpoint_store_error(
          checkpoint_store_error_code::snapshot_conflict, 0,
          "restart checkpoint identity already names different durable bytes");
    synchronize_fd(
        directory_fd_, checkpoint_store_error_code::directory_sync_failed,
        "cannot confirm checkpoint-store directory durability", true);
    return checkpoint;
  }

  try {
    publish_encoding(directory_fd_, name, encoding);
  }
  catch (const checkpoint_store_error& error) {
    if (error.code() != checkpoint_store_error_code::snapshot_conflict)
      throw;
    const auto current = read_encoding(directory_fd_, name);
    if (!current || *current != encoding)
      throw;
    synchronize_fd(
        directory_fd_, checkpoint_store_error_code::directory_sync_failed,
        "cannot confirm checkpoint-store directory durability", true);
  }
  return checkpoint;
}

template<class Request>
std::optional<application_restart_checkpoint> load_checkpoint(
    int directory_fd,
    const application_journal_record& journal,
    const Request& request)
{
  const auto encoding = read_encoding(
      directory_fd, storage_name(journal.identity()));
  if (!encoding)
    return std::nullopt;
  return decode_stored(*encoding, journal, request);
}

std::optional<application_restart_checkpoint>
application_restart_checkpoint_store::load(
    const application_journal_record& journal,
    const installation_application_request& request) const
{
  return load_checkpoint(directory_fd_, journal, request);
}

std::optional<application_restart_checkpoint>
application_restart_checkpoint_store::load(
    const application_journal_record& journal,
    const upgrade_application_request& request) const
{
  return load_checkpoint(directory_fd_, journal, request);
}

std::optional<application_restart_checkpoint>
application_restart_checkpoint_store::load(
    const application_journal_record& journal,
    const removal_application_request& request) const
{
  return load_checkpoint(directory_fd_, journal, request);
}

} // namespace pkgapply::posix
