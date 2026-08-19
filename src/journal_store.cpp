// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/journal_store.h>

#include <libpkgapply/journal_transport_codec.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
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

[[noreturn]] void throw_system(journal_store_error_code code,
                               std::string_view operation,
                               int error = errno,
                               bool publication_visible = false)
{
  throw journal_store_error(
      code, error, std::string(operation) + ": " + std::strerror(error),
      publication_visible);
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
    throw_system(journal_store_error_code::directory_open_failed,
                 "cannot set close-on-exec on journal-store descriptor");
#else
  static_cast<void>(fd);
#endif
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

void require_directory(int fd, std::string_view subject)
{
  struct stat status {};
  if (::fstat(fd, &status) != 0)
    throw_system(journal_store_error_code::directory_invalid,
                 std::string("cannot inspect ") + std::string(subject));
  if (!S_ISDIR(status.st_mode))
    throw journal_store_error(
        journal_store_error_code::directory_invalid, 0,
        std::string(subject) + " does not name a directory");
}

void require_regular(int fd, std::string_view subject)
{
  struct stat status {};
  if (::fstat(fd, &status) != 0)
    throw_system(journal_store_error_code::value_read_failed,
                 std::string("cannot inspect ") + std::string(subject));
  if (!S_ISREG(status.st_mode))
    throw journal_store_error(
        journal_store_error_code::value_corrupt, 0,
        std::string(subject) + " is not a regular file");
}

void synchronize_fd(int fd,
                    journal_store_error_code code,
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

std::string digest_suffix(std::string_view text, std::string_view subject)
{
  constexpr std::string_view prefix = "v1:sha256:";
  if (text.size() != prefix.size() + 64 ||
      text.compare(0, prefix.size(), prefix) != 0)
  {
    throw journal_store_error(
        journal_store_error_code::value_corrupt, 0,
        std::string(subject) + " identity has no supported storage representation");
  }
  return std::string(text.substr(prefix.size()));
}

std::string journal_name(const application_journal_declaration_identity& identity)
{
  return "journal-v1-sha256-" +
         digest_suffix(identity.string(), "journal declaration");
}

std::string active_name(const application_request_identity& identity)
{
  return "active-request-v1-sha256-" +
         digest_suffix(identity.string(), "application request") + ".ref";
}

std::string step_name(std::uint64_t sequence)
{
  std::array<char, 32> digits {};
  const auto result = std::to_chars(digits.data(), digits.data() + digits.size(),
                                    sequence);
  if (result.ec != std::errc())
    throw journal_store_error(journal_store_error_code::value_corrupt, 0,
                              "cannot format journal step sequence");
  const auto length = static_cast<std::size_t>(result.ptr - digits.data());
  std::string name(20U - length, '0');
  name.append(digits.data(), length);
  name += ".bin";
  return name;
}

std::string temporary_name(const std::string& final_name)
{
  const auto sequence = temporary_sequence.fetch_add(1, std::memory_order_relaxed);
  return final_name + ".tmp." + std::to_string(static_cast<long long>(::getpid())) +
         "." + std::to_string(sequence);
}

std::optional<application_journal_transport_encoding> read_encoding(
    int directory_fd,
    const std::string& name,
    std::string_view subject)
{
  const int flags = O_RDONLY | cloexec_flag() | nofollow_flag() | O_NONBLOCK;
  unique_fd file(open_at(directory_fd, name.c_str(), flags));
  if (file.get() < 0) {
    if (errno == ENOENT)
      return std::nullopt;
    throw_system(journal_store_error_code::value_open_failed,
                 std::string("cannot open ") + std::string(subject));
  }
  set_close_on_exec(file.get());
  require_regular(file.get(), subject);

  struct stat status {};
  if (::fstat(file.get(), &status) != 0)
    throw_system(journal_store_error_code::value_read_failed,
                 std::string("cannot size ") + std::string(subject));
  if (status.st_size < 0 ||
      static_cast<std::uint64_t>(status.st_size) >
          maximum_application_journal_transport_encoding_size)
  {
    throw journal_store_error(
        journal_store_error_code::value_corrupt, 0,
        std::string(subject) + " exceeds the owner transport size limit");
  }

  application_journal_transport_encoding bytes(
      static_cast<std::size_t>(status.st_size));
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto result = ::read(file.get(), bytes.data() + offset,
                               bytes.size() - offset);
    if (result < 0) {
      if (errno == EINTR)
        continue;
      throw_system(journal_store_error_code::value_read_failed,
                   std::string("cannot read ") + std::string(subject));
    }
    if (result == 0)
      throw journal_store_error(journal_store_error_code::value_corrupt, 0,
                                std::string(subject) + " was truncated while reading");
    offset += static_cast<std::size_t>(result);
  }

  std::uint8_t probe = 0;
  for (;;) {
    const auto result = ::read(file.get(), &probe, 1);
    if (result < 0 && errno == EINTR)
      continue;
    if (result < 0)
      throw_system(journal_store_error_code::value_read_failed,
                   std::string("cannot finish reading ") + std::string(subject));
    if (result != 0)
      throw journal_store_error(journal_store_error_code::value_corrupt, 0,
                                std::string(subject) + " changed size while reading");
    break;
  }
  return bytes;
}

void write_all(int fd, const application_journal_transport_encoding& bytes)
{
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto result = ::write(fd, bytes.data() + offset, bytes.size() - offset);
    if (result < 0) {
      if (errno == EINTR)
        continue;
      throw_system(journal_store_error_code::value_write_failed,
                   "cannot write journal transport bytes");
    }
    if (result == 0)
      throw journal_store_error(journal_store_error_code::value_write_failed, 0,
                                "journal transport write made no progress");
    offset += static_cast<std::size_t>(result);
  }
}

unique_fd write_temporary(int directory_fd,
                          const std::string& final_name,
                          const application_journal_transport_encoding& bytes,
                          std::string& temporary)
{
  unique_fd file;
  for (int attempt = 0; attempt < 128; ++attempt) {
    temporary = temporary_name(final_name);
    const int flags = O_WRONLY | O_CREAT | O_EXCL | cloexec_flag() |
                      nofollow_flag();
    file.reset(open_at(directory_fd, temporary.c_str(), flags, 0600));
    if (file.get() >= 0)
      break;
    if (errno != EEXIST)
      throw_system(journal_store_error_code::value_open_failed,
                   "cannot create temporary journal transport value");
  }
  if (file.get() < 0)
    throw journal_store_error(journal_store_error_code::value_open_failed,
                              EEXIST,
                              "cannot allocate a unique temporary journal value");
  set_close_on_exec(file.get());
  write_all(file.get(), bytes);
  synchronize_fd(file.get(), journal_store_error_code::value_sync_failed,
                 "cannot synchronize journal transport value");
  return file;
}

void publish_replacement(int directory_fd,
                         const std::string& final_name,
                         const application_journal_transport_encoding& bytes)
{
  std::string temporary;
  auto file = write_temporary(directory_fd, final_name, bytes, temporary);
  file.reset();
  for (;;) {
    if (::renameat(directory_fd, temporary.c_str(), directory_fd,
                   final_name.c_str()) == 0)
      break;
    if (errno != EINTR) {
      const int error = errno;
      static_cast<void>(::unlinkat(directory_fd, temporary.c_str(), 0));
      throw_system(journal_store_error_code::value_publish_failed,
                   "cannot atomically replace journal transport value", error);
    }
  }
  synchronize_fd(directory_fd, journal_store_error_code::directory_sync_failed,
                 "cannot synchronize journal namespace", true);
}

void publish_immutable(int directory_fd,
                       const std::string& final_name,
                       const application_journal_transport_encoding& bytes)
{
  if (const auto current = read_encoding(directory_fd, final_name,
                                         "immutable journal value")) {
    if (*current == bytes)
      return;
    throw journal_store_error(journal_store_error_code::immutable_conflict, 0,
                              "immutable journal value already differs");
  }

  std::string temporary;
  auto file = write_temporary(directory_fd, final_name, bytes, temporary);
  file.reset();

  for (;;) {
    if (::linkat(directory_fd, temporary.c_str(), directory_fd,
                 final_name.c_str(), 0) == 0)
      break;
    if (errno == EINTR)
      continue;
    if (errno == EEXIST) {
      static_cast<void>(::unlinkat(directory_fd, temporary.c_str(), 0));
      const auto current = read_encoding(directory_fd, final_name,
                                         "immutable journal value");
      if (current && *current == bytes)
        return;
      throw journal_store_error(journal_store_error_code::immutable_conflict, 0,
                                "concurrent immutable journal value differs");
    }
    const int error = errno;
    static_cast<void>(::unlinkat(directory_fd, temporary.c_str(), 0));
    throw_system(journal_store_error_code::value_publish_failed,
                 "cannot publish immutable journal value", error);
  }

  synchronize_fd(directory_fd, journal_store_error_code::directory_sync_failed,
                 "cannot synchronize immutable journal publication", true);
  if (::unlinkat(directory_fd, temporary.c_str(), 0) != 0 && errno != ENOENT)
    throw_system(journal_store_error_code::value_publish_failed,
                 "cannot remove immutable journal temporary link", errno, true);
  synchronize_fd(directory_fd, journal_store_error_code::directory_sync_failed,
                 "cannot synchronize immutable journal cleanup", true);
}

std::optional<unique_fd> open_child_directory(int parent_fd,
                                              const std::string& name,
                                              std::string_view subject)
{
  int flags = O_RDONLY | cloexec_flag() | nofollow_flag();
#ifdef O_DIRECTORY
  flags |= O_DIRECTORY;
#endif
  unique_fd fd(open_at(parent_fd, name.c_str(), flags));
  if (fd.get() < 0) {
    if (errno == ENOENT)
      return std::nullopt;
    throw_system(journal_store_error_code::namespace_open_failed,
                 std::string("cannot open ") + std::string(subject));
  }
  set_close_on_exec(fd.get());
  require_directory(fd.get(), subject);
  return std::optional<unique_fd>(std::move(fd));
}

unique_fd ensure_child_directory(int parent_fd,
                                 const std::string& name,
                                 std::string_view subject)
{
  bool created = false;
  if (::mkdirat(parent_fd, name.c_str(), 0700) != 0) {
    if (errno != EEXIST)
      throw_system(journal_store_error_code::namespace_open_failed,
                   std::string("cannot create ") + std::string(subject));
  } else {
    created = true;
  }
  auto opened = open_child_directory(parent_fd, name, subject);
  if (!opened)
    throw journal_store_error(journal_store_error_code::namespace_open_failed,
                              ENOENT,
                              std::string(subject) + " disappeared after creation");
  if (created)
    synchronize_fd(parent_fd, journal_store_error_code::directory_sync_failed,
                   std::string("cannot synchronize ") + std::string(subject) +
                       " parent");
  return std::move(*opened);
}

unique_fd open_required_journal(int root_fd,
                                const application_journal_declaration_identity& identity)
{
  auto journal = open_child_directory(root_fd, journal_name(identity),
                                      "journal declaration namespace");
  if (!journal)
    throw journal_store_error(journal_store_error_code::namespace_open_failed,
                              ENOENT,
                              "journal declaration namespace is absent");
  return std::move(*journal);
}

unique_fd open_required_steps(int journal_fd)
{
  auto steps = open_child_directory(journal_fd, "steps", "journal steps namespace");
  if (!steps)
    throw journal_store_error(journal_store_error_code::value_corrupt, ENOENT,
                              "journal steps namespace is absent");
  return std::move(*steps);
}

void require_declaration_file(int journal_fd)
{
  const int flags = O_RDONLY | cloexec_flag() | nofollow_flag() | O_NONBLOCK;
  unique_fd file(open_at(journal_fd, "declaration.bin", flags));
  if (file.get() < 0) {
    if (errno == ENOENT)
      throw journal_store_error(journal_store_error_code::value_corrupt, ENOENT,
                                "journal declaration bytes are absent");
    throw_system(journal_store_error_code::value_open_failed,
                 "cannot open journal declaration bytes");
  }
  set_close_on_exec(file.get());
  require_regular(file.get(), "journal declaration bytes");
}

application_journal_transport_encoding encode_active_reference(
    const application_journal_declaration_identity& declaration)
{
  const auto text = declaration.string() + "\n";
  return application_journal_transport_encoding(text.begin(), text.end());
}

application_journal_declaration_identity decode_active_reference(
    const application_journal_transport_encoding& bytes)
{
  constexpr std::size_t encoded_size = 10U + 64U + 1U;
  if (bytes.size() != encoded_size || bytes.back() != '\n')
    throw journal_store_error(journal_store_error_code::index_corrupt, 0,
                              "active request locator is malformed");
  try {
    return application_journal_declaration_identity::parse(
        std::string(bytes.begin(), bytes.end() - 1));
  } catch (const std::exception& error) {
    throw journal_store_error(journal_store_error_code::index_corrupt, 0,
                              std::string("active request locator is corrupt: ") +
                                  error.what());
  }
}

class cursor_lock final {
public:
  explicit cursor_lock(int journal_fd)
  {
    const int flags = O_RDWR | O_CREAT | cloexec_flag() | nofollow_flag() |
                      O_NONBLOCK;
    fd_.reset(open_at(journal_fd, "cursor.lock", flags, 0600));
    if (fd_.get() < 0)
      throw_system(journal_store_error_code::lock_failed,
                   "cannot open journal cursor lock");
    set_close_on_exec(fd_.get());
    require_regular(fd_.get(), "journal cursor lock");

    struct flock lock {};
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    for (;;) {
      if (::fcntl(fd_.get(), F_SETLKW, &lock) == 0)
        break;
      if (errno != EINTR)
        throw_system(journal_store_error_code::lock_failed,
                     "cannot acquire journal cursor lock");
    }
  }

private:
  unique_fd fd_;
};

application_journal_declaration decode_declaration(
    const application_journal_transport_encoding& bytes,
    const application_journal_declaration_identity& expected)
{
  try {
    auto value = decode_application_journal_declaration(bytes);
    if (value.identity() != expected)
      throw journal_store_error(journal_store_error_code::value_corrupt, 0,
                                "journal declaration filename and bytes disagree");
    return value;
  } catch (const journal_store_error&) {
    throw;
  } catch (const application_journal_transport_codec_error& error) {
    throw journal_store_error(journal_store_error_code::value_corrupt, 0,
                              std::string("journal declaration is corrupt: ") +
                                  error.what());
  }
}

application_journal_step decode_step(
    const application_journal_transport_encoding& bytes,
    const application_journal_declaration_identity& declaration,
    std::uint64_t sequence)
{
  try {
    auto value = decode_application_journal_step(bytes);
    if (value.declaration() != declaration || value.sequence() != sequence)
      throw journal_store_error(journal_store_error_code::value_corrupt, 0,
                                "journal step exact address and bytes disagree");
    return value;
  } catch (const journal_store_error&) {
    throw;
  } catch (const application_journal_transport_codec_error& error) {
    throw journal_store_error(journal_store_error_code::value_corrupt, 0,
                              std::string("journal step is corrupt: ") + error.what());
  }
}

application_journal_cursor decode_cursor(
    const application_journal_transport_encoding& bytes,
    const application_journal_declaration_identity& declaration)
{
  try {
    auto value = decode_application_journal_cursor(bytes);
    if (value.declaration() != declaration)
      throw journal_store_error(journal_store_error_code::value_corrupt, 0,
                                "journal cursor namespace and bytes disagree");
    return value;
  } catch (const journal_store_error&) {
    throw;
  } catch (const application_journal_transport_codec_error& error) {
    throw journal_store_error(journal_store_error_code::value_corrupt, 0,
                              std::string("journal cursor is corrupt: ") + error.what());
  }
}

} // namespace

journal_store_error::journal_store_error(journal_store_error_code code,
                                         int system_error,
                                         std::string message,
                                         bool publication_visible)
    : std::runtime_error(std::move(message)), code_(code),
      system_error_(system_error), publication_visible_(publication_visible)
{
}

journal_store_error::~journal_store_error() = default;

journal_store_error_code journal_store_error::code() const noexcept
{
  return code_;
}

int journal_store_error::system_error() const noexcept
{
  return system_error_;
}

bool journal_store_error::publication_visible() const noexcept
{
  return publication_visible_;
}

std::unique_ptr<application_journal_store> application_journal_store::open(
    const std::string& directory)
{
  if (directory.empty())
    throw journal_store_error(journal_store_error_code::directory_open_failed,
                              EINVAL, "journal-store directory path is empty");
  int flags = O_RDONLY | cloexec_flag() | nofollow_flag();
#ifdef O_DIRECTORY
  flags |= O_DIRECTORY;
#endif
  unique_fd fd(open_path(directory.c_str(), flags));
  if (fd.get() < 0)
    throw_system(journal_store_error_code::directory_open_failed,
                 "cannot open journal-store directory");
  set_close_on_exec(fd.get());
  require_directory(fd.get(), "journal-store descriptor");
  return std::unique_ptr<application_journal_store>(
      new application_journal_store(fd.release()));
}

std::unique_ptr<application_journal_store>
application_journal_store::from_directory_fd(int directory_fd)
{
  if (directory_fd < 0)
    throw journal_store_error(journal_store_error_code::directory_invalid,
                              EBADF,
                              "journal-store directory descriptor is invalid");
#ifdef F_DUPFD_CLOEXEC
  unique_fd duplicate(::fcntl(directory_fd, F_DUPFD_CLOEXEC, 0));
#else
  unique_fd duplicate(::dup(directory_fd));
#endif
  if (duplicate.get() < 0)
    throw_system(journal_store_error_code::directory_open_failed,
                 "cannot duplicate journal-store directory descriptor");
  set_close_on_exec(duplicate.get());
  require_directory(duplicate.get(), "journal-store descriptor");
  return std::unique_ptr<application_journal_store>(
      new application_journal_store(duplicate.release()));
}

application_journal_store::application_journal_store(int directory_fd) noexcept
    : directory_fd_(directory_fd)
{
}

application_journal_store::~application_journal_store()
{
  if (directory_fd_ >= 0)
    static_cast<void>(::close(directory_fd_));
}

application_journal_declaration application_journal_store::publish_declaration(
    const application_journal_declaration& declaration)
{
  auto journal = ensure_child_directory(directory_fd_, journal_name(declaration.identity()),
                                        "journal declaration namespace");
  static_cast<void>(ensure_child_directory(journal.get(), "steps",
                                           "journal steps namespace"));
  const auto bytes = encode_application_journal_declaration(declaration);
  publish_immutable(journal.get(), "declaration.bin", bytes);

  const auto locator = encode_active_reference(declaration.identity());
  publish_replacement(directory_fd_, active_name(declaration.header().request()), locator);
  return declaration;
}

application_journal_step application_journal_store::publish_step(
    const application_journal_step& step)
{
  auto journal = open_required_journal(directory_fd_, step.declaration());
  require_declaration_file(journal.get());
  auto steps = open_required_steps(journal.get());
  const auto bytes = encode_application_journal_step(step);
  publish_immutable(steps.get(), step_name(step.sequence()), bytes);
  return step;
}

application_journal_cursor application_journal_store::compare_and_publish_cursor(
    const std::optional<application_journal_cursor_identity>& expected,
    const application_journal_cursor& cursor)
{
  auto journal = open_required_journal(directory_fd_, cursor.declaration());
  require_declaration_file(journal.get());
  cursor_lock lock(journal.get());
  const auto current_bytes = read_encoding(journal.get(), "cursor.bin",
                                           "journal cursor");
  std::optional<application_journal_cursor> current;
  if (current_bytes)
    current = decode_cursor(*current_bytes, cursor.declaration());

  if (current && current->identity() == cursor.identity())
    return *current;
  if (expected) {
    if (!current || current->identity() != *expected)
      throw journal_store_error(journal_store_error_code::cursor_conflict, 0,
                                "journal cursor compare-and-publish expectation is stale");
  } else if (current) {
    throw journal_store_error(journal_store_error_code::cursor_conflict, 0,
                              "initial journal cursor is already published");
  }

  const auto bytes = encode_application_journal_cursor(cursor);
  publish_replacement(journal.get(), "cursor.bin", bytes);
  return cursor;
}

std::optional<application_journal_declaration>
application_journal_store::load_declaration(
    const application_journal_declaration_identity& identity)
{
  auto journal = open_child_directory(directory_fd_, journal_name(identity),
                                      "journal declaration namespace");
  if (!journal)
    return std::nullopt;
  const auto bytes = read_encoding(journal->get(), "declaration.bin",
                                   "journal declaration");
  if (!bytes)
    return std::nullopt;
  return decode_declaration(*bytes, identity);
}

std::optional<application_journal_cursor> application_journal_store::load_cursor(
    const application_journal_declaration_identity& declaration)
{
  auto journal = open_child_directory(directory_fd_, journal_name(declaration),
                                      "journal declaration namespace");
  if (!journal)
    return std::nullopt;
  const auto bytes = read_encoding(journal->get(), "cursor.bin", "journal cursor");
  if (!bytes)
    return std::nullopt;
  return decode_cursor(*bytes, declaration);
}

std::optional<application_journal_step> application_journal_store::load_step(
    const application_journal_declaration_identity& declaration,
    std::uint64_t sequence)
{
  auto journal = open_child_directory(directory_fd_, journal_name(declaration),
                                      "journal declaration namespace");
  if (!journal)
    return std::nullopt;
  auto steps = open_child_directory(journal->get(), "steps", "journal steps namespace");
  if (!steps)
    return std::nullopt;
  const auto bytes = read_encoding(steps->get(), step_name(sequence), "journal step");
  if (!bytes)
    return std::nullopt;
  return decode_step(*bytes, declaration, sequence);
}

std::optional<application_journal_declaration_identity>
application_journal_store::load_active_declaration(
    const application_request_identity& request)
{
  const auto bytes = read_encoding(directory_fd_, active_name(request),
                                   "active request locator");
  if (!bytes)
    return std::nullopt;
  const auto identity = decode_active_reference(*bytes);
  const auto declaration = load_declaration(identity);
  if (!declaration)
    throw journal_store_error(journal_store_error_code::index_corrupt, ENOENT,
                              "active request locator references a missing declaration");
  if (declaration->header().request() != request)
    throw journal_store_error(journal_store_error_code::index_corrupt, 0,
                              "active request locator references another request");
  return identity;
}

} // namespace pkgapply::posix
