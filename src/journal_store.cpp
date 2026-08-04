// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/journal_store.h>

#include <libpkgapply/journal_codec.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <optional>
#include <stdexcept>
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
    journal_store_error_code code,
    std::string_view operation,
    int error = errno,
    bool replacement_visible = false)
{
  throw journal_store_error(
      code, error,
      std::string(operation) + ": " + std::strerror(error),
      replacement_visible);
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
    journal_store_error_code code,
    std::string_view operation,
    bool replacement_visible = false)
{
  for (;;) {
    if (::fsync(fd) == 0)
      return;
    if (errno != EINTR)
      throw_system(code, operation, errno, replacement_visible);
  }
}

void replace_at(
    int directory_fd,
    const std::string& temporary,
    const std::string& final_name)
{
  for (;;) {
    if (::renameat(
            directory_fd, temporary.c_str(), directory_fd,
            final_name.c_str()) == 0)
    {
      return;
    }
    if (errno != EINTR)
      throw_system(
          journal_store_error_code::snapshot_rename_failed,
          "cannot replace journal snapshot");
  }
}

void require_directory(int fd)
{
  struct stat status {};
  if (::fstat(fd, &status) != 0)
    throw_system(
        journal_store_error_code::directory_invalid,
        "cannot inspect journal-store directory");
  if (!S_ISDIR(status.st_mode))
    throw journal_store_error(
        journal_store_error_code::directory_invalid, 0,
        "journal-store descriptor does not name a directory");
}

std::string storage_name(const application_journal_identity& identity)
{
  const auto& text = identity.string();
  constexpr std::string_view prefix = "v1:sha256:";
  if (text.size() != prefix.size() + 64 ||
      text.compare(0, prefix.size(), prefix) != 0)
  {
    throw journal_store_error(
        journal_store_error_code::snapshot_corrupt, 0,
        "journal identity has no supported storage representation");
  }
  return "journal-v1-sha256-" + text.substr(prefix.size()) + ".bin";
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
        journal_store_error_code::directory_open_failed,
        "cannot set close-on-exec on journal-store descriptor");
#else
  static_cast<void>(fd);
#endif
}

std::optional<application_journal_encoding> read_encoding(
    int directory_fd,
    const std::string& name)
{
  const int flags = O_RDONLY | cloexec_flag() | nofollow_flag();
  unique_fd file(open_at(directory_fd, name.c_str(), flags));
  if (file.get() < 0) {
    if (errno == ENOENT)
      return std::nullopt;
    throw_system(
        journal_store_error_code::snapshot_open_failed,
        "cannot open journal snapshot");
  }
  set_close_on_exec(file.get());

  struct stat status {};
  if (::fstat(file.get(), &status) != 0)
    throw_system(
        journal_store_error_code::snapshot_read_failed,
        "cannot inspect journal snapshot");
  if (!S_ISREG(status.st_mode))
    throw journal_store_error(
        journal_store_error_code::snapshot_corrupt, 0,
        "journal snapshot is not a regular file");
  if (status.st_size < 0 ||
      static_cast<std::uint64_t>(status.st_size) >
          maximum_application_journal_encoding_size)
  {
    throw journal_store_error(
        journal_store_error_code::snapshot_corrupt, 0,
        "journal snapshot exceeds the encoding size limit");
  }

  application_journal_encoding bytes(
      static_cast<std::size_t>(status.st_size));
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto result = ::read(
        file.get(), bytes.data() + offset, bytes.size() - offset);
    if (result < 0) {
      if (errno == EINTR)
        continue;
      throw_system(
          journal_store_error_code::snapshot_read_failed,
          "cannot read journal snapshot");
    }
    if (result == 0)
      throw journal_store_error(
          journal_store_error_code::snapshot_corrupt, 0,
          "journal snapshot was truncated while reading");
    offset += static_cast<std::size_t>(result);
  }

  std::uint8_t probe = 0;
  for (;;) {
    const auto result = ::read(file.get(), &probe, 1);
    if (result < 0 && errno == EINTR)
      continue;
    if (result < 0)
      throw_system(
          journal_store_error_code::snapshot_read_failed,
          "cannot finish reading journal snapshot");
    if (result != 0)
      throw journal_store_error(
          journal_store_error_code::snapshot_corrupt, 0,
          "journal snapshot changed size while reading");
    break;
  }
  return bytes;
}

application_journal_record decode_stored(
    const application_journal_encoding& encoding,
    const application_journal_identity& expected)
{
  try {
    auto record = decode_application_journal(encoding);
    if (record.header().identity() != expected)
      throw journal_store_error(
          journal_store_error_code::snapshot_corrupt, 0,
          "journal snapshot filename and content disagree");
    return record;
  } catch (const journal_store_error&) {
    throw;
  } catch (const application_journal_codec_error& error) {
    throw journal_store_error(
        journal_store_error_code::snapshot_corrupt, 0,
        std::string("journal snapshot is corrupt: ") + error.what());
  }
}

void write_all(int fd, const application_journal_encoding& bytes)
{
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto result = ::write(fd, bytes.data() + offset, bytes.size() - offset);
    if (result < 0) {
      if (errno == EINTR)
        continue;
      throw_system(
          journal_store_error_code::snapshot_write_failed,
          "cannot write journal snapshot");
    }
    if (result == 0)
      throw journal_store_error(
          journal_store_error_code::snapshot_write_failed, 0,
          "journal snapshot write made no progress");
    offset += static_cast<std::size_t>(result);
  }
}

std::string temporary_name(const std::string& final_name)
{
  const auto sequence = temporary_sequence.fetch_add(1, std::memory_order_relaxed);
  return final_name + ".tmp." + std::to_string(static_cast<long long>(::getpid())) +
         "." + std::to_string(sequence);
}

void publish_encoding(
    int directory_fd,
    const std::string& final_name,
    const application_journal_encoding& bytes)
{
  std::string temporary;
  unique_fd file;
  for (int attempt = 0; attempt < 128; ++attempt) {
    temporary = temporary_name(final_name);
    const int flags = O_WRONLY | O_CREAT | O_EXCL | cloexec_flag() |
                      nofollow_flag();
    file.reset(open_at(directory_fd, temporary.c_str(), flags, 0600));
    if (file.get() >= 0)
      break;
    if (errno != EEXIST)
      throw_system(
          journal_store_error_code::snapshot_open_failed,
          "cannot create temporary journal snapshot");
  }
  if (file.get() < 0)
    throw journal_store_error(
        journal_store_error_code::snapshot_open_failed, EEXIST,
        "cannot allocate a unique temporary journal snapshot");
  set_close_on_exec(file.get());

  try {
    write_all(file.get(), bytes);
    synchronize_fd(
        file.get(), journal_store_error_code::snapshot_sync_failed,
        "cannot synchronize temporary journal snapshot");
    file.reset();

    replace_at(directory_fd, temporary, final_name);
    temporary.clear();
    synchronize_fd(
        directory_fd, journal_store_error_code::directory_sync_failed,
        "cannot synchronize journal-store directory", true);
  } catch (...) {
    if (!temporary.empty())
      static_cast<void>(::unlinkat(directory_fd, temporary.c_str(), 0));
    throw;
  }
}

} // namespace

journal_store_error::journal_store_error(
    journal_store_error_code code,
    int system_error,
    std::string message,
    bool replacement_visible)
    : std::runtime_error(std::move(message)), code_(code),
      system_error_(system_error), replacement_visible_(replacement_visible)
{
}

journal_store_error_code journal_store_error::code() const noexcept
{
  return code_;
}

int journal_store_error::system_error() const noexcept
{
  return system_error_;
}

bool journal_store_error::replacement_visible() const noexcept
{
  return replacement_visible_;
}

application_journal_store application_journal_store::open(
    const std::string& directory)
{
  if (directory.empty())
    throw journal_store_error(
        journal_store_error_code::directory_open_failed, EINVAL,
        "journal-store directory path is empty");
  int flags = O_RDONLY | cloexec_flag() | nofollow_flag();
#ifdef O_DIRECTORY
  flags |= O_DIRECTORY;
#endif
  unique_fd fd(open_path(directory.c_str(), flags));
  if (fd.get() < 0)
    throw_system(
        journal_store_error_code::directory_open_failed,
        "cannot open journal-store directory");
  set_close_on_exec(fd.get());
  require_directory(fd.get());
  return application_journal_store(fd.release());
}

application_journal_store application_journal_store::from_directory_fd(
    int directory_fd)
{
  if (directory_fd < 0)
    throw journal_store_error(
        journal_store_error_code::directory_invalid, EBADF,
        "journal-store directory descriptor is invalid");
#ifdef F_DUPFD_CLOEXEC
  unique_fd duplicate(::fcntl(directory_fd, F_DUPFD_CLOEXEC, 0));
#else
  unique_fd duplicate(::dup(directory_fd));
#endif
  if (duplicate.get() < 0)
    throw_system(
        journal_store_error_code::directory_open_failed,
        "cannot duplicate journal-store directory descriptor");
  set_close_on_exec(duplicate.get());
  require_directory(duplicate.get());
  return application_journal_store(duplicate.release());
}

application_journal_store::application_journal_store(int directory_fd) noexcept
    : directory_fd_(directory_fd)
{
}

application_journal_store::application_journal_store(
    application_journal_store&& other) noexcept
    : directory_fd_(other.directory_fd_)
{
  other.directory_fd_ = -1;
}

application_journal_store& application_journal_store::operator=(
    application_journal_store&& other) noexcept
{
  if (this != &other) {
    if (directory_fd_ >= 0)
      static_cast<void>(::close(directory_fd_));
    directory_fd_ = other.directory_fd_;
    other.directory_fd_ = -1;
  }
  return *this;
}

application_journal_store::~application_journal_store()
{
  if (directory_fd_ >= 0)
    static_cast<void>(::close(directory_fd_));
}

application_journal_record application_journal_store::publish(
    const application_journal_record& record)
{
  const auto name = storage_name(record.header().identity());
  if (const auto current = read_encoding(directory_fd_, name)) {
    const auto previous = decode_stored(*current, record.header().identity());
    try {
      validate_application_journal_successor(previous, record);
    } catch (const application_journal_transition_error& error) {
      throw journal_store_error(
          journal_store_error_code::snapshot_conflict, 0,
          std::string("journal snapshot replacement conflicts: ") +
              error.what());
    }
    if (previous.identity() == record.identity()) {
      synchronize_fd(
          directory_fd_, journal_store_error_code::directory_sync_failed,
          "cannot confirm journal-store directory durability", true);
      return previous;
    }
  }

  const auto encoding = encode_application_journal(record);
  publish_encoding(directory_fd_, name, encoding);
  return record;
}

std::optional<application_journal_record> application_journal_store::load(
    const application_journal_identity& journal) const
{
  const auto name = storage_name(journal);
  const auto encoding = read_encoding(directory_fd_, name);
  if (!encoding)
    return std::nullopt;
  return decode_stored(*encoding, journal);
}

} // namespace pkgapply::posix
