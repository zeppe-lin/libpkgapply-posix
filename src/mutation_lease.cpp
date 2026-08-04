// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/mutation_lease.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <fcntl.h>
#include <openssl/rand.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace pkgapply::posix {
namespace {

class owned_fd final {
public:
  explicit owned_fd(int value = -1) noexcept : value_(value) {}
  owned_fd(const owned_fd&) = delete;
  owned_fd& operator=(const owned_fd&) = delete;
  owned_fd(owned_fd&& other) noexcept : value_(other.release()) {}
  owned_fd& operator=(owned_fd&& other) noexcept
  {
    if (this != &other) {
      reset();
      value_ = other.release();
    }
    return *this;
  }
  ~owned_fd() { reset(); }

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

[[noreturn]] void
throw_error(target_mutation_lease_error_code code,
            int system_error,
            std::string message)
{
  throw target_mutation_lease_error(code, system_error, std::move(message));
}

std::string
lock_name(const mutation_exclusion_domain_identity& domain)
{
  constexpr std::string_view prefix = "v1:sha256:";
  const std::string& identity = domain.string();
  if (identity.size() != prefix.size() + 64 ||
      identity.compare(0, prefix.size(), prefix) != 0)
  {
    throw std::logic_error("noncanonical mutation exclusion-domain identity");
  }
  return "mutation-v1-sha256-" + identity.substr(prefix.size()) + ".lock";
}

bool
same_file(const struct stat& lhs, const struct stat& rhs) noexcept
{
  return lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino;
}

mutation_lease_nonce
random_nonce()
{
  mutation_lease_nonce::byte_array bytes{};
  if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
    throw_error(target_mutation_lease_error_code::nonce_failed, 0,
                "cannot obtain an unpredictable mutation-lease nonce");
  }
  return mutation_lease_nonce::from_bytes(bytes);
}

} // namespace

class target_mutation_lease::implementation final {
public:
  implementation(mutation_lease_acquisition acquisition,
                 owned_fd directory,
                 owned_fd lock,
                 std::string name,
                 struct stat file)
      : acquisition_(std::move(acquisition)), directory_(std::move(directory)),
        lock_(std::move(lock)), name_(std::move(name)), file_(file)
  {
  }

  [[nodiscard]] bool held() const noexcept
  {
    if (directory_.get() < 0 || lock_.get() < 0)
      return false;

    struct stat descriptor {};
    if (::fstat(lock_.get(), &descriptor) != 0 ||
        !S_ISREG(descriptor.st_mode) || descriptor.st_nlink == 0 ||
        !same_file(descriptor, file_))
    {
      return false;
    }

    struct stat named {};
    if (::fstatat(directory_.get(), name_.c_str(), &named,
                  AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(named.st_mode) || named.st_nlink == 0 ||
        !same_file(named, file_))
    {
      return false;
    }
    return true;
  }

  mutation_lease_acquisition acquisition_;
  owned_fd directory_;
  owned_fd lock_;
  std::string name_;
  struct stat file_ {};
};

target_mutation_lease_error::target_mutation_lease_error(
    target_mutation_lease_error_code code,
    int system_error,
    std::string message)
    : std::runtime_error(std::move(message)), code_(code),
      system_error_(system_error)
{
}

target_mutation_lease_error_code
target_mutation_lease_error::code() const noexcept
{
  return code_;
}

int
target_mutation_lease_error::system_error() const noexcept
{
  return system_error_;
}

std::unique_ptr<target_mutation_lease>
target_mutation_lease::acquire(
    const application_target_context& target,
    int lock_directory_fd)
{
  struct stat supplied {};
  if (lock_directory_fd < 0 || ::fstat(lock_directory_fd, &supplied) != 0 ||
      !S_ISDIR(supplied.st_mode))
  {
    const int failure = lock_directory_fd < 0 ? EBADF : errno;
    throw_error(target_mutation_lease_error_code::directory_invalid, failure,
                "target mutation lease requires a directory descriptor");
  }

  owned_fd directory(::fcntl(lock_directory_fd, F_DUPFD_CLOEXEC, 0));
  if (directory.get() < 0) {
    throw_error(target_mutation_lease_error_code::directory_duplicate_failed,
                errno, "cannot duplicate target mutation lock directory");
  }

  const std::string name = lock_name(target.mutation_exclusion_domain());
  owned_fd lock(::openat(directory.get(), name.c_str(),
                         O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                         S_IRUSR | S_IWUSR));
  if (lock.get() < 0) {
    throw_error(target_mutation_lease_error_code::lock_open_failed, errno,
                "cannot open target mutation lock file");
  }

  struct stat file {};
  if (::fstat(lock.get(), &file) != 0) {
    throw_error(target_mutation_lease_error_code::lock_open_failed, errno,
                "cannot inspect target mutation lock file");
  }
  if (!S_ISREG(file.st_mode) || file.st_nlink == 0) {
    throw_error(target_mutation_lease_error_code::lock_not_regular, 0,
                "target mutation lock is not a linked regular file");
  }

  if (::flock(lock.get(), LOCK_EX | LOCK_NB) != 0) {
    const int failure = errno;
    if (failure == EWOULDBLOCK || failure == EAGAIN) {
      throw_error(target_mutation_lease_error_code::lock_busy, failure,
                  "target mutation exclusion domain is already held");
    }
    throw_error(target_mutation_lease_error_code::lock_failed, failure,
                "cannot acquire target mutation lock");
  }

  struct stat named {};
  const int named_result = ::fstatat(
      directory.get(), name.c_str(), &named, AT_SYMLINK_NOFOLLOW);
  const int named_failure = named_result == 0 ? 0 : errno;
  if (named_result != 0 || !S_ISREG(named.st_mode) || named.st_nlink == 0 ||
      !same_file(named, file))
  {
    throw_error(target_mutation_lease_error_code::lock_replaced,
                named_failure,
                "target mutation lock changed during acquisition");
  }

  auto acquisition = mutation_lease_acquisition::make(
      target.identity(), target.mutation_exclusion_domain(), random_nonce());
  return std::unique_ptr<target_mutation_lease>(
      new target_mutation_lease(std::make_unique<implementation>(
          std::move(acquisition), std::move(directory), std::move(lock), name,
          file)));
}

target_mutation_lease::target_mutation_lease(
    std::unique_ptr<implementation> state)
    : state_(std::move(state))
{
}

target_mutation_lease::~target_mutation_lease() = default;

const mutation_lease_instance_identity&
target_mutation_lease::identity() const noexcept
{
  return state_->acquisition_.identity();
}

const application_target_context_identity&
target_mutation_lease::target() const noexcept
{
  return state_->acquisition_.target();
}

const mutation_exclusion_domain_identity&
target_mutation_lease::exclusion_domain() const noexcept
{
  return state_->acquisition_.exclusion_domain();
}

bool
target_mutation_lease::held() const noexcept
{
  return state_->held();
}

} // namespace pkgapply::posix
