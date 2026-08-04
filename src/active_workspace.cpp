// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "active_workspace.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

namespace pkgapply::posix::detail {
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

struct evp_context_deleter final {
  void operator()(EVP_MD_CTX* context) const noexcept
  {
    EVP_MD_CTX_free(context);
  }
};

[[noreturn]] void
throw_error(active_workspace_error_code code,
            int system_error,
            const pkgplan::package_path& path,
            std::string message)
{
  throw active_workspace_error(
      code, system_error, path.string(), std::move(message));
}

void
require_directory(int fd)
{
  struct stat status {};
  if (::fstat(fd, &status) != 0)
    throw active_workspace_error(
        active_workspace_error_code::target_root_invalid, errno, {},
        "cannot inspect active target-root descriptor");
  if (!S_ISDIR(status.st_mode))
    throw active_workspace_error(
        active_workspace_error_code::target_root_invalid, ENOTDIR, {},
        "active target-root descriptor is not a directory");
}

int
duplicate_fd(int fd)
{
#ifdef F_DUPFD_CLOEXEC
  const int duplicate = ::fcntl(fd, F_DUPFD_CLOEXEC, 0);
#else
  const int duplicate = ::dup(fd);
  if (duplicate >= 0) {
    const int flags = ::fcntl(duplicate, F_GETFD);
    if (flags < 0 || ::fcntl(duplicate, F_SETFD, flags | FD_CLOEXEC) != 0) {
      const int saved = errno;
      static_cast<void>(::close(duplicate));
      errno = saved;
      return -1;
    }
  }
#endif
  return duplicate;
}

int
open_directory_at(int parent, const std::string& component)
{
  for (;;) {
    const int fd = ::openat(
        parent, component.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0 || errno != EINTR)
      return fd;
  }
}

std::array<std::uint8_t, 32>
workspace_digest(const application_attempt& attempt,
                 const pkgplan::package_path& path)
{
  std::unique_ptr<EVP_MD_CTX, evp_context_deleter> context(EVP_MD_CTX_new());
  if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
    throw std::runtime_error("cannot initialize active workspace digest");

  constexpr std::string_view domain =
      "libpkgapply.posix-active-workspace-name.v1";
  const auto& attempt_bytes = attempt.identity().bytes();
  const std::string& path_text = path.string();
  std::array<std::uint8_t, 8> path_size {};
  std::uint64_t size = path_text.size();
  for (std::size_t index = 0; index < path_size.size(); ++index) {
    path_size[path_size.size() - index - 1] =
        static_cast<std::uint8_t>(size & 0xffU);
    size >>= 8U;
  }
  if (EVP_DigestUpdate(context.get(), domain.data(), domain.size()) != 1 ||
      EVP_DigestUpdate(context.get(), attempt_bytes.data(),
                       attempt_bytes.size()) != 1 ||
      EVP_DigestUpdate(
          context.get(), path_size.data(), path_size.size()) != 1 ||
      EVP_DigestUpdate(context.get(), path_text.data(), path_text.size()) != 1)
  {
    throw std::runtime_error("cannot update active workspace digest");
  }

  std::array<std::uint8_t, 32> result {};
  unsigned int result_size = 0;
  if (EVP_DigestFinal_ex(context.get(), result.data(), &result_size) != 1 ||
      result_size != result.size())
  {
    throw std::runtime_error("cannot finalize active workspace digest");
  }
  return result;
}

std::string
hexadecimal_prefix(const std::array<std::uint8_t, 32>& digest)
{
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(32);
  for (std::size_t index = 0; index < 16; ++index) {
    result.push_back(digits[digest[index] >> 4]);
    result.push_back(digits[digest[index] & 0x0fU]);
  }
  return result;
}

bool
leaf_present(int parent,
             const std::string& name,
             const pkgplan::package_path& path)
{
  struct stat status {};
  for (;;) {
    if (::fstatat(parent, name.c_str(), &status, AT_SYMLINK_NOFOLLOW) == 0)
      return true;
    if (errno == EINTR)
      continue;
    if (errno == ENOENT)
      return false;
    throw_error(
        active_workspace_error_code::workspace_inspection_failed,
        errno, path, "cannot inspect active workspace leaf");
  }
}

} // namespace

active_workspace_error::active_workspace_error(
    active_workspace_error_code code,
    int system_error,
    std::string path,
    std::string message)
    : std::runtime_error(std::move(message)), code_(code),
      system_error_(system_error), path_(std::move(path))
{
}

active_workspace_error_code active_workspace_error::code() const noexcept
{
  return code_;
}

int active_workspace_error::system_error() const noexcept
{
  return system_error_;
}

const std::string& active_workspace_error::path() const noexcept
{
  return path_;
}

active_workspace_snapshot::active_workspace_snapshot(
    active_workspace_state state,
    bool final_present,
    bool prepared_present,
    bool displaced_present) noexcept
    : state_(state), final_present_(final_present),
      prepared_present_(prepared_present),
      displaced_present_(displaced_present)
{
}

active_workspace_state active_workspace_snapshot::state() const noexcept
{
  return state_;
}

bool active_workspace_snapshot::final_present() const noexcept
{
  return final_present_;
}

bool active_workspace_snapshot::prepared_present() const noexcept
{
  return prepared_present_;
}

bool active_workspace_snapshot::displaced_present() const noexcept
{
  return displaced_present_;
}

active_path_workspace::active_path_workspace(
    int parent_fd,
    pkgplan::package_path path,
    std::string leaf,
    std::string prepared_name,
    std::string displaced_name) noexcept
    : parent_fd_(parent_fd), path_(std::move(path)), leaf_(std::move(leaf)),
      prepared_name_(std::move(prepared_name)),
      displaced_name_(std::move(displaced_name))
{
}

active_path_workspace::active_path_workspace(
    active_path_workspace&& other) noexcept
    : parent_fd_(other.parent_fd_), path_(std::move(other.path_)),
      leaf_(std::move(other.leaf_)),
      prepared_name_(std::move(other.prepared_name_)),
      displaced_name_(std::move(other.displaced_name_))
{
  other.parent_fd_ = -1;
}

active_path_workspace& active_path_workspace::operator=(
    active_path_workspace&& other) noexcept
{
  if (this != &other) {
    if (parent_fd_ >= 0)
      static_cast<void>(::close(parent_fd_));
    parent_fd_ = other.parent_fd_;
    path_ = std::move(other.path_);
    leaf_ = std::move(other.leaf_);
    prepared_name_ = std::move(other.prepared_name_);
    displaced_name_ = std::move(other.displaced_name_);
    other.parent_fd_ = -1;
  }
  return *this;
}

active_path_workspace::~active_path_workspace()
{
  if (parent_fd_ >= 0)
    static_cast<void>(::close(parent_fd_));
}

int active_path_workspace::parent_descriptor() const noexcept
{
  return parent_fd_;
}

const pkgplan::package_path& active_path_workspace::path() const noexcept
{
  return path_;
}

const std::string& active_path_workspace::leaf() const noexcept
{
  return leaf_;
}

const std::string& active_path_workspace::prepared_name() const noexcept
{
  return prepared_name_;
}

const std::string& active_path_workspace::displaced_name() const noexcept
{
  return displaced_name_;
}

active_workspace_snapshot active_path_workspace::inspect() const
{
  const bool final_present = leaf_present(parent_fd_, leaf_, path_);
  const bool prepared_present =
      leaf_present(parent_fd_, prepared_name_, path_);
  const bool displaced_present =
      leaf_present(parent_fd_, displaced_name_, path_);

  active_workspace_state state = active_workspace_state::contradictory;
  if (!prepared_present && !displaced_present) {
    state = active_workspace_state::clear;
  } else if (prepared_present && !displaced_present) {
    state = active_workspace_state::prepared;
  } else if (prepared_present && displaced_present && !final_present) {
    state = active_workspace_state::displaced;
  } else if (!prepared_present && displaced_present && !final_present) {
    state = active_workspace_state::removed_with_displaced_old;
  } else if (!prepared_present && displaced_present && final_present) {
    state = active_workspace_state::published_with_displaced_old;
  }
  return active_workspace_snapshot(
      state, final_present, prepared_present, displaced_present);
}

application_active_workspace application_active_workspace::from_directory_fd(
    int target_root_fd,
    application_attempt attempt)
{
  require_directory(target_root_fd);
  const int duplicate = duplicate_fd(target_root_fd);
  if (duplicate < 0)
    throw active_workspace_error(
        active_workspace_error_code::target_root_invalid, errno, {},
        "cannot duplicate active target-root descriptor");
  return application_active_workspace(duplicate, std::move(attempt));
}

application_active_workspace::application_active_workspace(
    int target_root_fd,
    application_attempt attempt) noexcept
    : target_root_fd_(target_root_fd), attempt_(std::move(attempt))
{
}

application_active_workspace::application_active_workspace(
    application_active_workspace&& other) noexcept
    : target_root_fd_(other.target_root_fd_),
      attempt_(std::move(other.attempt_))
{
  other.target_root_fd_ = -1;
}

application_active_workspace& application_active_workspace::operator=(
    application_active_workspace&& other) noexcept
{
  if (this != &other) {
    if (target_root_fd_ >= 0)
      static_cast<void>(::close(target_root_fd_));
    target_root_fd_ = other.target_root_fd_;
    attempt_ = std::move(other.attempt_);
    other.target_root_fd_ = -1;
  }
  return *this;
}

application_active_workspace::~application_active_workspace()
{
  if (target_root_fd_ >= 0)
    static_cast<void>(::close(target_root_fd_));
}

const application_attempt&
application_active_workspace::attempt() const noexcept
{
  return attempt_;
}

int application_active_workspace::target_root_descriptor() const noexcept
{
  return target_root_fd_;
}

active_path_workspace application_active_workspace::open(
    const pkgplan::package_path& path) const
{
  const std::string& text = path.string();
  const std::size_t slash = text.rfind('/');
  const std::string leaf = slash == std::string::npos
      ? text
      : text.substr(slash + 1);
  if (leaf.empty())
    throw_error(active_workspace_error_code::path_resolution_failed,
                EINVAL, path, "active path has an empty leaf");

  unique_fd parent(duplicate_fd(target_root_fd_));
  if (parent.get() < 0)
    throw_error(active_workspace_error_code::path_resolution_failed,
                errno, path, "cannot duplicate active target root");

  std::size_t offset = 0;
  const std::size_t end = slash == std::string::npos ? 0 : slash;
  while (offset < end) {
    const std::size_t separator = text.find('/', offset);
    const std::size_t component_end =
        separator == std::string::npos ? end : separator;
    const std::string component =
        text.substr(offset, component_end - offset);
    unique_fd next(open_directory_at(parent.get(), component));
    if (next.get() < 0)
      throw_error(active_workspace_error_code::path_resolution_failed,
                  errno, path, "cannot resolve active path parent");
    parent = std::move(next);
    offset = component_end + 1;
  }

  const std::string token =
      hexadecimal_prefix(workspace_digest(attempt_, path));
  return active_path_workspace(
      parent.release(), path, leaf,
      ".libpkgapply-new-" + token,
      ".libpkgapply-old-" + token);
}

} // namespace pkgapply::posix::detail
