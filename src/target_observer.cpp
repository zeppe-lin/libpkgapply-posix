// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/target_observer.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
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

struct evp_context_deleter final {
  void operator()(EVP_MD_CTX* context) const noexcept
  {
    EVP_MD_CTX_free(context);
  }
};

struct resolved_leaf final {
  owned_fd parent;
  std::string leaf;
  bool parent_missing;
};

[[noreturn]] void
throw_error(target_observer_error_code code,
            int system_error,
            const pkgplan::package_path& path,
            const char* message)
{
  throw target_observer_error(code, system_error, path.string(), message);
}

bool
same_object(const struct stat& lhs, const struct stat& rhs) noexcept
{
  return lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino &&
      lhs.st_mode == rhs.st_mode && lhs.st_uid == rhs.st_uid &&
      lhs.st_gid == rhs.st_gid && lhs.st_size == rhs.st_size &&
      lhs.st_mtim.tv_sec == rhs.st_mtim.tv_sec &&
      lhs.st_mtim.tv_nsec == rhs.st_mtim.tv_nsec &&
      lhs.st_ctim.tv_sec == rhs.st_ctim.tv_sec &&
      lhs.st_ctim.tv_nsec == rhs.st_ctim.tv_nsec;
}

std::vector<std::string_view>
components(const pkgplan::package_path& path)
{
  std::vector<std::string_view> result;
  const std::string& value = path.string();
  std::size_t begin = 0;
  while (begin < value.size()) {
    const std::size_t end = value.find('/', begin);
    result.push_back(std::string_view(value).substr(
        begin, end == std::string::npos ? value.size() - begin : end - begin));
    if (end == std::string::npos)
      break;
    begin = end + 1;
  }
  return result;
}

resolved_leaf
resolve_parent(int root_fd, const pkgplan::package_path& path)
{
  const auto parts = components(path);
  owned_fd current(::fcntl(root_fd, F_DUPFD_CLOEXEC, 0));
  if (current.get() < 0)
    throw_error(target_observer_error_code::root_invalid, errno, path,
                "cannot duplicate target root descriptor");

  for (std::size_t index = 0; index + 1 < parts.size(); ++index) {
    const std::string component(parts[index]);
    const int next = ::openat(current.get(), component.c_str(),
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (next >= 0) {
      current.reset(next);
      continue;
    }

    const int failure = errno;
    if (failure == ENOENT)
      return resolved_leaf{std::move(current), std::string(parts.back()), true};

    struct stat metadata {};
    if (::fstatat(current.get(), component.c_str(), &metadata,
                  AT_SYMLINK_NOFOLLOW) == 0)
    {
      if (S_ISLNK(metadata.st_mode))
        throw_error(target_observer_error_code::path_resolution_failed,
                    ELOOP, path,
                    "target path contains a symbolic-link parent");
      if (!S_ISDIR(metadata.st_mode))
        return resolved_leaf{std::move(current), std::string(parts.back()), true};
    }
    throw_error(target_observer_error_code::path_resolution_failed,
                failure, path, "cannot resolve target path parent");
  }

  return resolved_leaf{std::move(current), std::string(parts.back()), false};
}

std::array<std::uint8_t, 32>
hash_regular(int fd, const pkgplan::package_path& path)
{
  std::unique_ptr<EVP_MD_CTX, evp_context_deleter> context(EVP_MD_CTX_new());
  if (!context)
    throw_error(target_observer_error_code::content_hash_failed, 0, path,
                "cannot allocate content hash context");
  if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
    throw_error(target_observer_error_code::content_hash_failed, 0, path,
                "cannot initialize content hash");

  std::array<std::byte, 65536> buffer{};
  for (;;) {
    const ssize_t count = ::read(fd, buffer.data(), buffer.size());
    if (count > 0) {
      if (EVP_DigestUpdate(context.get(), buffer.data(),
                           static_cast<std::size_t>(count)) != 1)
      {
        throw_error(target_observer_error_code::content_hash_failed, 0, path,
                    "cannot update content hash");
      }
      continue;
    }
    if (count == 0)
      break;
    if (errno == EINTR)
      continue;
    throw_error(target_observer_error_code::object_read_failed, errno, path,
                "cannot read regular target object");
  }

  std::array<std::uint8_t, 32> digest{};
  unsigned int size = 0;
  if (EVP_DigestFinal_ex(context.get(), digest.data(), &size) != 1 ||
      size != digest.size())
  {
    throw_error(target_observer_error_code::content_hash_failed, 0, path,
                "cannot finalize content hash");
  }
  return digest;
}

std::string
digest_text(const std::array<std::uint8_t, 32>& digest)
{
  static constexpr char digits[] = "0123456789abcdef";
  std::string result = "v1:sha256:";
  result.reserve(result.size() + digest.size() * 2);
  for (const std::uint8_t byte : digest) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 0x0f]);
  }
  return result;
}

completed_object_kind
object_kind(mode_t mode) noexcept
{
  if (S_ISREG(mode)) return completed_object_kind::regular;
  if (S_ISDIR(mode)) return completed_object_kind::directory;
  if (S_ISLNK(mode)) return completed_object_kind::symlink;
  if (S_ISFIFO(mode)) return completed_object_kind::fifo;
  if (S_ISCHR(mode)) return completed_object_kind::character_device;
  if (S_ISBLK(mode)) return completed_object_kind::block_device;
  if (S_ISSOCK(mode)) return completed_object_kind::socket;
  return completed_object_kind::other;
}

const target_hardlink_expectation*
find_hardlink(const std::vector<target_hardlink_expectation>& values,
              const pkgplan::package_path& path) noexcept
{
  const auto item = std::lower_bound(
      values.begin(), values.end(), path,
      [](const auto& value, const auto& wanted) { return value.path() < wanted; });
  return item != values.end() && item->path() == path ? &*item : nullptr;
}

std::optional<struct stat>
stat_leaf(int root_fd, const pkgplan::package_path& path)
{
  resolved_leaf leaf = resolve_parent(root_fd, path);
  if (leaf.parent_missing)
    return std::nullopt;
  struct stat metadata {};
  if (::fstatat(leaf.parent.get(), leaf.leaf.c_str(), &metadata,
                AT_SYMLINK_NOFOLLOW) == 0)
  {
    return metadata;
  }
  if (errno == ENOENT)
    return std::nullopt;
  throw_error(target_observer_error_code::object_stat_failed, errno, path,
              "cannot stat target object");
}

application_path_observation
observe_one(int root_fd,
            const pkgplan::package_path& path,
            const std::vector<target_hardlink_expectation>& hardlinks)
{
  resolved_leaf leaf = resolve_parent(root_fd, path);
  if (leaf.parent_missing)
    return application_path_observation::absent(path);

  struct stat before {};
  if (::fstatat(leaf.parent.get(), leaf.leaf.c_str(), &before,
                AT_SYMLINK_NOFOLLOW) != 0)
  {
    if (errno == ENOENT)
      return application_path_observation::absent(path);
    throw_error(target_observer_error_code::object_stat_failed, errno, path,
                "cannot stat target object");
  }

  struct stat stable = before;
  auto size = qualified_fact<std::uint64_t>::not_applicable();
  auto content =
      qualified_fact<completed_regular_content_identity>::not_applicable();
  auto symlink = qualified_fact<std::string>::not_applicable();
  auto device = qualified_fact<completed_device_number>::not_applicable();
  auto hardlink =
      qualified_fact<completed_hardlink_relation>::not_applicable();
  object_fact_completeness completeness = object_fact_completeness::complete;

  const completed_object_kind kind = object_kind(before.st_mode);
  if (kind == completed_object_kind::regular) {
    const int raw = ::openat(leaf.parent.get(), leaf.leaf.c_str(),
                             O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (raw < 0) {
      if (errno == ENOENT)
        return application_path_observation::unknown(path);
      throw_error(target_observer_error_code::object_open_failed, errno, path,
                  "cannot open regular target object");
    }
    owned_fd object(raw);
    struct stat opened {};
    if (::fstat(object.get(), &opened) != 0)
      throw_error(target_observer_error_code::object_stat_failed, errno, path,
                  "cannot stat opened regular target object");
    if (!S_ISREG(opened.st_mode) || !same_object(before, opened))
      return application_path_observation::unknown(path);

    const auto digest = hash_regular(object.get(), path);
    struct stat after {};
    if (::fstat(object.get(), &after) != 0)
      throw_error(target_observer_error_code::object_stat_failed, errno, path,
                  "cannot restat regular target object");
    if (!same_object(opened, after))
      return application_path_observation::unknown(path);
    stable = after;

    size = qualified_fact<std::uint64_t>::known(
        static_cast<std::uint64_t>(after.st_size));
    content = qualified_fact<completed_regular_content_identity>::known(
        completed_regular_content_identity::parse(digest_text(digest)));
    hardlink = qualified_fact<completed_hardlink_relation>::unknown();
    completeness = object_fact_completeness::partial;

    if (const auto* expectation = find_hardlink(hardlinks, path)) {
      const auto anchor = stat_leaf(root_fd, expectation->anchor());
      if (!anchor || !S_ISREG(anchor->st_mode) ||
          anchor->st_dev != after.st_dev || anchor->st_ino != after.st_ino)
      {
        return application_path_observation::unknown(path);
      }
      hardlink = qualified_fact<completed_hardlink_relation>::known(
          completed_hardlink_relation(expectation->anchor()));
      completeness = object_fact_completeness::complete;
    }
  } else if (kind == completed_object_kind::symlink) {
    constexpr std::size_t maximum_symlink_size = 1024U * 1024U;
    if (before.st_size < 0 ||
        static_cast<std::uint64_t>(before.st_size) > maximum_symlink_size)
    {
      throw_error(target_observer_error_code::object_read_failed, EOVERFLOW,
                  path, "target symbolic link is too large");
    }
    std::vector<char> bytes(static_cast<std::size_t>(before.st_size) + 1U);
    for (;;) {
      const ssize_t count = ::readlinkat(leaf.parent.get(), leaf.leaf.c_str(),
                                         bytes.data(), bytes.size());
      if (count < 0) {
        if (errno == ENOENT)
          return application_path_observation::unknown(path);
        throw_error(target_observer_error_code::object_read_failed, errno, path,
                    "cannot read target symbolic link");
      }
      if (static_cast<std::size_t>(count) < bytes.size()) {
        bytes.resize(static_cast<std::size_t>(count));
        break;
      }
      if (bytes.size() >= maximum_symlink_size)
        throw_error(target_observer_error_code::object_read_failed, EOVERFLOW,
                    path, "target symbolic link is too large");
      bytes.resize(std::min(maximum_symlink_size, bytes.size() * 2U + 1U));
    }
    struct stat after {};
    if (::fstatat(leaf.parent.get(), leaf.leaf.c_str(), &after,
                  AT_SYMLINK_NOFOLLOW) != 0 || !same_object(before, after))
    {
      return application_path_observation::unknown(path);
    }
    stable = after;
    symlink = qualified_fact<std::string>::known(
        std::string(bytes.begin(), bytes.end()));
  } else if (kind == completed_object_kind::character_device ||
             kind == completed_object_kind::block_device)
  {
    device = qualified_fact<completed_device_number>::known(
        {static_cast<std::uint64_t>(::major(before.st_rdev)),
         static_cast<std::uint64_t>(::minor(before.st_rdev))});
  }

  const auto mode = qualified_fact<std::uint32_t>::known(
      static_cast<std::uint32_t>(stable.st_mode & 07777));
  const auto uid = qualified_fact<std::uint64_t>::known(stable.st_uid);
  const auto gid = qualified_fact<std::uint64_t>::known(stable.st_gid);
  const auto mtime = qualified_fact<completed_object_timestamp>::known(
      {stable.st_mtim.tv_sec,
       static_cast<std::uint32_t>(stable.st_mtim.tv_nsec)});

  return application_path_observation::present(completed_object_fact(
      path, kind, std::move(mode), std::move(uid), std::move(gid),
      std::move(size), std::move(mtime), std::move(content),
      std::move(symlink), std::move(device), std::move(hardlink),
      object_fact_provenance::application_observation, completeness));
}

void
normalize_hardlinks(std::vector<target_hardlink_expectation>& values,
                    const std::vector<pkgplan::package_path>& paths)
{
  std::sort(values.begin(), values.end(), [](const auto& lhs, const auto& rhs) {
    return lhs.path() < rhs.path();
  });
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index != 0 && values[index - 1].path() == values[index].path())
      throw std::invalid_argument("duplicate target hard-link expectation");
    if (!std::binary_search(paths.begin(), paths.end(), values[index].path()) ||
        !std::binary_search(paths.begin(), paths.end(), values[index].anchor()))
    {
      throw std::invalid_argument(
          "target hard-link expectation lies outside observation closure");
    }
  }
}

} // namespace

target_observer_error::target_observer_error(
    target_observer_error_code code,
    int system_error,
    std::string path,
    std::string message)
    : std::runtime_error(std::move(message)), code_(code),
      system_error_(system_error), path_(std::move(path))
{
}

target_observer_error_code target_observer_error::code() const noexcept
{ return code_; }
int target_observer_error::system_error() const noexcept
{ return system_error_; }
const std::string& target_observer_error::path() const noexcept
{ return path_; }

target_hardlink_expectation::target_hardlink_expectation(
    pkgplan::package_path path,
    pkgplan::package_path anchor)
    : path_(std::move(path)), anchor_(std::move(anchor))
{
  if (path_ == anchor_)
    throw std::invalid_argument("hard-link expectation names itself");
}
const pkgplan::package_path& target_hardlink_expectation::path() const noexcept
{ return path_; }
const pkgplan::package_path& target_hardlink_expectation::anchor() const noexcept
{ return anchor_; }

application_target_observer application_target_observer::open(
    const std::string& root)
{
  const int fd = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    throw target_observer_error(target_observer_error_code::root_open_failed,
                                errno, root, "cannot open target root");
  return application_target_observer(fd);
}

application_target_observer application_target_observer::from_directory_fd(
    int directory_fd)
{
  struct stat metadata {};
  if (::fstat(directory_fd, &metadata) != 0)
    throw target_observer_error(target_observer_error_code::root_invalid,
                                errno, {}, "target root descriptor is invalid");
  if (!S_ISDIR(metadata.st_mode))
    throw target_observer_error(target_observer_error_code::root_invalid,
                                ENOTDIR, {}, "target root descriptor is invalid");
  const int duplicate = ::fcntl(directory_fd, F_DUPFD_CLOEXEC, 0);
  if (duplicate < 0)
    throw target_observer_error(target_observer_error_code::root_invalid,
                                errno, {}, "cannot duplicate target root descriptor");
  return application_target_observer(duplicate);
}

application_target_observer::application_target_observer(int root_fd) noexcept
    : root_fd_(root_fd)
{
}
application_target_observer::application_target_observer(
    application_target_observer&& other) noexcept
    : root_fd_(other.root_fd_)
{
  other.root_fd_ = -1;
}
application_target_observer& application_target_observer::operator=(
    application_target_observer&& other) noexcept
{
  if (this != &other) {
    if (root_fd_ >= 0)
      static_cast<void>(::close(root_fd_));
    root_fd_ = other.root_fd_;
    other.root_fd_ = -1;
  }
  return *this;
}
application_target_observer::~application_target_observer()
{
  if (root_fd_ >= 0)
    static_cast<void>(::close(root_fd_));
}

backend_observation_batch application_target_observer::observe(
    std::vector<pkgplan::package_path> paths,
    std::vector<target_hardlink_expectation> hardlinks) const
{
  if (root_fd_ < 0)
    throw target_observer_error(target_observer_error_code::root_invalid,
                                EBADF, {}, "target observer is not open");
  std::sort(paths.begin(), paths.end());
  if (std::adjacent_find(paths.begin(), paths.end()) != paths.end())
    throw std::invalid_argument("duplicate target observation path");
  normalize_hardlinks(hardlinks, paths);

  std::vector<application_path_observation> observations;
  observations.reserve(paths.size());
  for (const auto& path : paths)
    observations.push_back(observe_one(root_fd_, path, hardlinks));
  return backend_observation_batch::make(
      std::move(paths), std::move(observations));
}

} // namespace pkgapply::posix
