// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/mutation_lease.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

void
require(bool condition, std::string_view message)
{
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

template<class Identity>
Identity
application_identity(std::uint8_t value)
{
  std::string text = "v1:sha256:";
  constexpr char hexadecimal[] = "0123456789abcdef";
  for (std::size_t index = 0; index < 32; ++index) {
    const auto byte = static_cast<std::uint8_t>(value + index);
    text += hexadecimal[(byte >> 4) & 0x0fU];
    text += hexadecimal[byte & 0x0fU];
  }
  return Identity::parse(text);
}

template<class Identity>
Identity
planning_identity(std::uint8_t value)
{
  std::array<std::uint8_t, 32> bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index)
    bytes[index] = static_cast<std::uint8_t>(value + index);
  return Identity::from_sha256(bytes);
}

pkgapply::application_target_context
target_with_domain(
    std::uint8_t offset,
    pkgapply::mutation_exclusion_domain_identity domain)
{
  return pkgapply::application_target_context::make(
      planning_identity<pkgplan::target_system_context_identity>(1 + offset),
      application_identity<pkgapply::managed_target_identity>(2 + offset),
      application_identity<pkgapply::root_view_identity>(3 + offset),
      application_identity<pkgapply::observation_backend_identity>(4 + offset),
      application_identity<pkgapply::mutation_backend_identity>(5 + offset),
      std::move(domain),
      application_identity<pkgapply::active_object_namespace_identity>(
          7 + offset),
      application_identity<pkgapply::rejected_object_store_identity>(8 + offset),
      application_identity<pkgapply::staging_namespace_identity>(9 + offset),
      application_identity<pkgapply::journal_namespace_identity>(10 + offset),
      application_identity<pkgapply::execution_capability_profile_identity>(
          11 + offset));
}

pkgapply::application_target_context
target(std::uint8_t offset = 0)
{
  return target_with_domain(
      offset,
      application_identity<pkgapply::mutation_exclusion_domain_identity>(
          6 + offset));
}

pkgapply::lease_bound_state_projection
state(const pkgapply::mutation_lease_instance_identity& lease)
{
  return pkgapply::lease_bound_state_projection::make(
      lease,
      planning_identity<pkgplan::installed_state_snapshot_identity>(70),
      planning_identity<pkgplan::ownership_inventory_identity>(71),
      pkgapply::state_projection_completeness::complete,
      {},
      application_identity<pkgapply::state_projection_evidence_identity>(72));
}

class temporary_directory final {
public:
  temporary_directory()
  {
    char pattern[] = "/tmp/libpkgapply-lease-XXXXXX";
    char* value = ::mkdtemp(pattern);
    if (!value)
      throw std::runtime_error("cannot create temporary directory");
    path_ = value;
  }

  ~temporary_directory()
  {
    const std::string command = "rm -rf -- '" + path_ + "'";
    static_cast<void>(std::system(command.c_str()));
  }

  [[nodiscard]] const std::string& path() const noexcept { return path_; }

private:
  std::string path_;
};

std::string
lock_name(const pkgapply::mutation_exclusion_domain_identity& domain)
{
  return "mutation-v1-sha256-" + domain.string().substr(10) + ".lock";
}

int
open_directory(const std::string& path)
{
  const int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0)
    throw std::runtime_error("cannot open test directory");
  return fd;
}

} // namespace

int
main()
{
  temporary_directory directory;
  const int directory_fd = open_directory(directory.path());
  const auto context = target();
  const std::string name = lock_name(context.mutation_exclusion_domain());
  const std::string path = directory.path() + "/" + name;

  auto lease = pkgapply::posix::target_mutation_lease::acquire(
      context, directory_fd);
  require(lease->held(), "new POSIX target mutation lease is not held");
  require(lease->target() == context.identity(),
          "POSIX lease retained another target context");
  require(lease->exclusion_domain() == context.mutation_exclusion_domain(),
          "POSIX lease retained another exclusion domain");
  pkgapply::validate_target_mutation_lease(context, state(lease->identity()),
                                           *lease);

  struct stat lock_metadata {};
  require(::lstat(path.c_str(), &lock_metadata) == 0 &&
              S_ISREG(lock_metadata.st_mode),
          "POSIX lease did not retain one regular lock file");

  bool busy = false;
  try {
    static_cast<void>(pkgapply::posix::target_mutation_lease::acquire(
        context, directory_fd));
  } catch (const pkgapply::posix::target_mutation_lease_error& error) {
    busy = error.code() ==
        pkgapply::posix::target_mutation_lease_error_code::lock_busy;
  }
  require(busy, "competing POSIX lease acquisition did not fail immediately");

  const auto shared_domain_target = target_with_domain(
      20, context.mutation_exclusion_domain());
  bool shared_domain_busy = false;
  try {
    static_cast<void>(pkgapply::posix::target_mutation_lease::acquire(
        shared_domain_target, directory_fd));
  } catch (const pkgapply::posix::target_mutation_lease_error& error) {
    shared_domain_busy = error.code() ==
        pkgapply::posix::target_mutation_lease_error_code::lock_busy;
  }
  require(shared_domain_busy,
          "shared exclusion domain did not exclude another target context");

  lease.reset();
  require(::lstat(path.c_str(), &lock_metadata) == 0,
          "POSIX lease destructor removed the coordination file");
  auto reacquired = pkgapply::posix::target_mutation_lease::acquire(
      context, directory_fd);
  require(reacquired->held(), "released POSIX lease could not be reacquired");

  require(::unlink(path.c_str()) == 0,
          "cannot remove held test coordination file");
  const int replacement = ::open(path.c_str(),
      O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
  require(replacement >= 0, "cannot replace held test coordination file");
  require(::close(replacement) == 0,
          "cannot close replacement coordination file");
  require(!reacquired->held(),
          "POSIX lease claimed authority after lock-file replacement");
  reacquired.reset();

  const auto linked_context = target(30);
  const std::string linked_name =
      lock_name(linked_context.mutation_exclusion_domain());
  const std::string linked_path = directory.path() + "/" + linked_name;
  require(::symlink("elsewhere", linked_path.c_str()) == 0,
          "cannot create test lock symlink");
  bool symlink_rejected = false;
  try {
    static_cast<void>(pkgapply::posix::target_mutation_lease::acquire(
        linked_context, directory_fd));
  } catch (const pkgapply::posix::target_mutation_lease_error& error) {
    symlink_rejected = error.code() ==
        pkgapply::posix::target_mutation_lease_error_code::lock_open_failed;
  }
  require(symlink_rejected, "POSIX lease followed a lock-file symlink");

  bool invalid_rejected = false;
  try {
    static_cast<void>(pkgapply::posix::target_mutation_lease::acquire(
        context, -1));
  } catch (const pkgapply::posix::target_mutation_lease_error& error) {
    invalid_rejected = error.code() ==
        pkgapply::posix::target_mutation_lease_error_code::directory_invalid;
  }
  require(invalid_rejected, "POSIX lease accepted an invalid directory");

  temporary_directory anchored;
  const int anchored_fd = open_directory(anchored.path());
  const std::string moved = anchored.path() + "-moved";
  require(::rename(anchored.path().c_str(), moved.c_str()) == 0,
          "cannot rename test lock directory");
  auto anchored_lease = pkgapply::posix::target_mutation_lease::acquire(
      target(60), anchored_fd);
  require(anchored_lease->held(),
          "POSIX lease followed a replaced directory pathname");
  require(::rename(moved.c_str(), anchored.path().c_str()) == 0,
          "cannot restore test lock directory");

  require(::close(anchored_fd) == 0,
          "cannot close anchored lock directory descriptor");
  require(::close(directory_fd) == 0,
          "cannot close test lock directory descriptor");
  require(anchored_lease->held(),
          "lease depended on the caller's directory descriptor lifetime");
  return 0;
}
