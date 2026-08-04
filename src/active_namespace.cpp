// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "active_namespace.h"

#include <libpkgapply-posix/target_observer.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <dirent.h>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
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

[[nodiscard]] bool
equal_digest_bytes(const std::array<std::uint8_t, 32>& lhs,
                   const pkgimage::digest_bytes& rhs) noexcept
{
  return lhs.size() == rhs.size() &&
      std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

[[nodiscard]] backend_operation_result
operation(backend_operation_outcome outcome)
{
  return backend_operation_result(outcome);
}

[[nodiscard]] int
duplicate_fd(int descriptor)
{
#ifdef F_DUPFD_CLOEXEC
  return ::fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
#else
  const int duplicate = ::dup(descriptor);
  if (duplicate >= 0) {
    const int flags = ::fcntl(duplicate, F_GETFD);
    if (flags < 0 || ::fcntl(duplicate, F_SETFD, flags | FD_CLOEXEC) != 0) {
      const int saved = errno;
      static_cast<void>(::close(duplicate));
      errno = saved;
      return -1;
    }
  }
  return duplicate;
#endif
}

[[nodiscard]] std::optional<struct stat>
stat_leaf(int parent, const std::string& name)
{
  struct stat status {};
  for (;;) {
    if (::fstatat(parent, name.c_str(), &status, AT_SYMLINK_NOFOLLOW) == 0)
      return status;
    if (errno == EINTR)
      continue;
    if (errno == ENOENT)
      return std::nullopt;
    throw std::runtime_error("cannot inspect active namespace leaf");
  }
}

void
remove_prepared(const active_path_workspace& workspace,
                pkgimage::entry_type type) noexcept
{
  const int flags = type == pkgimage::entry_type::directory
      ? AT_REMOVEDIR
      : 0;
  static_cast<void>(::unlinkat(
      workspace.parent_descriptor(), workspace.prepared_name().c_str(),
      flags));
}

[[nodiscard]] bool
same_inode_metadata(const pkgimage::package_entry& lhs,
                    const pkgimage::package_entry& rhs) noexcept
{
  return lhs.mode == rhs.mode && lhs.uid == rhs.uid && lhs.gid == rhs.gid &&
      lhs.mtime == rhs.mtime &&
      lhs.mtime_nanoseconds == rhs.mtime_nanoseconds;
}

void
validate_hard_links(const pkgimage::package_image& image)
{
  for (const auto& entry : image.entries()) {
    if (entry.type != pkgimage::entry_type::hardlink)
      continue;
    if (!entry.hardlink_target)
      throw std::invalid_argument("incoming hard link lacks its anchor");
    const auto* anchor = image.find(*entry.hardlink_target);
    if (anchor == nullptr || anchor->type != pkgimage::entry_type::regular)
      throw std::invalid_argument("incoming hard-link anchor is not regular");
    if (!same_inode_metadata(entry, *anchor)) {
      throw std::invalid_argument(
          "incoming hard-link metadata differs from its regular anchor");
    }
  }
}

void
validate_binding(const application_active_workspace& workspace,
                 const pkgimage::package_image& image,
                 const sealed_application_payloads* payloads)
{
  if (payloads == nullptr)
    return;
  if (payloads->attempt().identity() != workspace.attempt().identity() ||
      payloads->image() != image.identity())
  {
    throw std::invalid_argument(
        "active namespace payload authority binding mismatch");
  }
}

[[nodiscard]] bool
same_observation(const application_path_observation& lhs,
                 const application_path_observation& rhs) noexcept
{
  if (lhs.path() != rhs.path() || lhs.state() != rhs.state())
    return false;
  if (lhs.object().has_value() != rhs.object().has_value())
    return false;
  return !lhs.object() || *lhs.object() == *rhs.object();
}

[[nodiscard]] bool
same_object_without_hardlink(const completed_object_fact& lhs,
                             const completed_object_fact& rhs) noexcept
{
  return lhs.path() == rhs.path() && lhs.kind() == rhs.kind() &&
      lhs.mode() == rhs.mode() && lhs.uid() == rhs.uid() &&
      lhs.gid() == rhs.gid() && lhs.size() == rhs.size() &&
      lhs.mtime() == rhs.mtime() &&
      lhs.regular_content() == rhs.regular_content() &&
      lhs.symlink_target() == rhs.symlink_target() &&
      lhs.device() == rhs.device();
}

[[nodiscard]] bool
same_regular_inode(int member_parent,
                   const std::string& member_name,
                   int anchor_parent,
                   const std::string& anchor_name)
{
  const auto member = stat_leaf(member_parent, member_name);
  const auto anchor = stat_leaf(anchor_parent, anchor_name);
  return member && anchor && S_ISREG(member->st_mode) &&
      S_ISREG(anchor->st_mode) && member->st_dev == anchor->st_dev &&
      member->st_ino == anchor->st_ino;
}

[[nodiscard]] bool
still_admitted(const application_active_workspace& roots,
               const application_path_observation& admitted)
{
  application_target_observer observer =
      application_target_observer::from_directory_fd(
          roots.target_root_descriptor());

  const bool known_hardlink = admitted.object() &&
      admitted.object()->hardlink().state() == fact_state::known &&
      admitted.object()->hardlink().value();
  if (!known_hardlink) {
    backend_observation_batch observed = observer.observe(
        {admitted.path()}, {});
    const auto* current = observed.find(admitted.path());
    return current != nullptr && same_observation(admitted, *current);
  }

  backend_observation_batch observed = observer.observe(
      {admitted.path()}, {});
  const auto* current = observed.find(admitted.path());
  if (current == nullptr || current->state() != admitted.state() ||
      !current->object() ||
      !same_object_without_hardlink(*admitted.object(), *current->object()))
  {
    return false;
  }

  active_path_workspace member = roots.open(admitted.path());
  const auto& anchor_path =
      admitted.object()->hardlink().value()->anchor();
  active_path_workspace anchor = roots.open(anchor_path);
  const active_workspace_snapshot anchor_state = anchor.inspect();
  if (anchor_state.state() == active_workspace_state::contradictory)
    return false;

  const std::string& anchor_name = anchor_state.displaced_present()
      ? anchor.displaced_name()
      : anchor.leaf();
  return same_regular_inode(
      member.parent_descriptor(), member.leaf(),
      anchor.parent_descriptor(), anchor_name);
}


void
normalize_admitted(std::vector<application_path_observation>& admitted)
{
  std::sort(
      admitted.begin(), admitted.end(),
      [](const auto& lhs, const auto& rhs) {
        return lhs.path() < rhs.path();
      });
  const auto duplicate = std::adjacent_find(
      admitted.begin(), admitted.end(),
      [](const auto& lhs, const auto& rhs) {
        return lhs.path() == rhs.path();
      });
  if (duplicate != admitted.end())
    throw std::invalid_argument("duplicate admitted active observation");
}

void
validate_captures(
    const application_active_workspace& workspace,
    const std::vector<application_path_observation>& admitted,
    const std::vector<captured_old_object>& captures)
{
  std::vector<pkgplan::package_path> paths;
  paths.reserve(captures.size());
  for (const auto& captured : captures) {
    if (captured.attempt().identity() != workspace.attempt().identity() ||
        !captured.request().for_recovery())
    {
      throw std::invalid_argument("active recovery capture binding mismatch");
    }
    const auto found = std::lower_bound(
        admitted.begin(), admitted.end(), captured.request().path(),
        [](const auto& observation, const auto& path) {
          return observation.path() < path;
        });
    if (found == admitted.end() ||
        found->path() != captured.request().path() ||
        !same_observation(*found, captured.observation()))
    {
      throw std::invalid_argument(
          "active recovery capture changed observation");
    }
    paths.push_back(captured.request().path());
  }
  std::sort(paths.begin(), paths.end());
  if (std::adjacent_find(paths.begin(), paths.end()) != paths.end())
    throw std::invalid_argument("duplicate active recovery capture");
}


[[nodiscard]] const pkgimage::package_entry&
resolve_entry(const pkgimage::package_image& image,
              const backend_active_effect_request& request)
{
  if (request.outcome() != pkgplan::planned_active_outcome::activate_incoming ||
      !request.incoming_entry())
  {
    throw std::invalid_argument(
        "incoming publication requires an activate-incoming request");
  }
  const auto* entry = image.entry(*request.incoming_entry());
  if (entry == nullptr || entry->path.string() != request.path().string())
    throw std::invalid_argument("active request cites another image entry");
  return *entry;
}

[[nodiscard]] std::array<std::uint8_t, 32>
copy_regular_payload(int source,
                     int destination,
                     std::uint64_t expected_size)
{
  std::unique_ptr<EVP_MD_CTX, evp_context_deleter> context(EVP_MD_CTX_new());
  if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
    throw std::runtime_error("cannot initialize active payload digest");

  std::array<std::byte, 64U * 1024U> buffer {};
  std::uint64_t copied = 0;
  for (;;) {
    ssize_t count;
    do {
      count = ::read(source, buffer.data(), buffer.size());
    } while (count < 0 && errno == EINTR);
    if (count < 0)
      throw std::runtime_error("cannot read sealed active payload");
    if (count == 0)
      break;
    const auto amount = static_cast<std::size_t>(count);
    std::size_t offset = 0;
    while (offset < amount) {
      ssize_t written;
      do {
        written = ::write(
            destination, buffer.data() + offset, amount - offset);
      } while (written < 0 && errno == EINTR);
      if (written <= 0)
        throw std::runtime_error("cannot write prepared active payload");
      offset += static_cast<std::size_t>(written);
    }
    if (EVP_DigestUpdate(context.get(), buffer.data(), amount) != 1)
      throw std::runtime_error("cannot update active payload digest");
    copied += static_cast<std::uint64_t>(amount);
  }
  if (copied != expected_size)
    throw std::runtime_error("sealed active payload size changed");

  std::array<std::uint8_t, 32> digest {};
  unsigned int size = 0;
  if (EVP_DigestFinal_ex(context.get(), digest.data(), &size) != 1 ||
      size != digest.size())
  {
    throw std::runtime_error("cannot finalize active payload digest");
  }
  return digest;
}

[[nodiscard]] bool
apply_descriptor_metadata(int descriptor,
                          const pkgimage::package_entry& entry)
{
  if (::fchown(descriptor, static_cast<uid_t>(entry.uid),
               static_cast<gid_t>(entry.gid)) != 0)
    return false;
  if (::fchmod(descriptor, static_cast<mode_t>(entry.mode & 07777U)) != 0)
    return false;
  const struct timespec times[2] = {
      {0, UTIME_OMIT},
      {entry.mtime, static_cast<long>(entry.mtime_nanoseconds)},
  };
  return ::futimens(descriptor, times) == 0;
}

[[nodiscard]] bool
apply_path_metadata(int parent,
                    const std::string& name,
                    const pkgimage::package_entry& entry,
                    bool symbolic_link)
{
  if (::fchownat(parent, name.c_str(), static_cast<uid_t>(entry.uid),
                 static_cast<gid_t>(entry.gid), AT_SYMLINK_NOFOLLOW) != 0)
    return false;
  if (!symbolic_link &&
      ::fchmodat(parent, name.c_str(),
                 static_cast<mode_t>(entry.mode & 07777U), 0) != 0)
    return false;
  const struct timespec times[2] = {
      {0, UTIME_OMIT},
      {entry.mtime, static_cast<long>(entry.mtime_nanoseconds)},
  };
  return ::utimensat(
      parent, name.c_str(), times,
      symbolic_link ? AT_SYMLINK_NOFOLLOW : 0) == 0;
}

[[nodiscard]] unique_fd
prepare_regular(const active_path_workspace& workspace,
                const pkgimage::package_entry& entry,
                const sealed_application_payloads* payloads)
{
  if (payloads == nullptr)
    return unique_fd();
  staged_regular_payload payload = payloads->open(entry.id);
  unique_fd file(::openat(
      workspace.parent_descriptor(), workspace.prepared_name().c_str(),
      O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (file.get() < 0)
    return unique_fd();
  try {
    const auto digest = copy_regular_payload(
        payload.descriptor(), file.get(), payload.size());
    if (!entry.regular_content ||
        !equal_digest_bytes(digest, entry.regular_content->bytes()) ||
        payload.size() != entry.size ||
        !apply_descriptor_metadata(file.get(), entry))
    {
      remove_prepared(workspace, entry.type);
      return unique_fd();
    }
  } catch (...) {
    remove_prepared(workspace, entry.type);
    throw;
  }
  return file;
}

[[nodiscard]] unique_fd
prepare_directory(const active_path_workspace& workspace,
                  const pkgimage::package_entry& entry)
{
  if (::mkdirat(workspace.parent_descriptor(),
                workspace.prepared_name().c_str(), 0700) != 0)
    return unique_fd();
  unique_fd directory(::openat(
      workspace.parent_descriptor(), workspace.prepared_name().c_str(),
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (directory.get() < 0 ||
      !apply_descriptor_metadata(directory.get(), entry))
  {
    remove_prepared(workspace, entry.type);
    return unique_fd();
  }
  return directory;
}

[[nodiscard]] bool
prepare_symlink(const active_path_workspace& workspace,
                const pkgimage::package_entry& entry)
{
  if (!entry.symlink_target ||
      ::symlinkat(entry.symlink_target->c_str(), workspace.parent_descriptor(),
                  workspace.prepared_name().c_str()) != 0)
    return false;
  if (!apply_path_metadata(workspace.parent_descriptor(),
                           workspace.prepared_name(), entry, true))
  {
    remove_prepared(workspace, entry.type);
    return false;
  }
  const auto status = stat_leaf(
      workspace.parent_descriptor(), workspace.prepared_name());
  if (!status || !S_ISLNK(status->st_mode) ||
      static_cast<std::uint32_t>(status->st_mode & 07777) !=
          (entry.mode & 07777U))
  {
    remove_prepared(workspace, entry.type);
    return false;
  }
  return true;
}

[[nodiscard]] bool
prepare_special(const active_path_workspace& workspace,
                const pkgimage::package_entry& entry)
{
  mode_t type = 0;
  dev_t device = 0;
  switch (entry.type) {
    case pkgimage::entry_type::fifo:
      type = S_IFIFO;
      break;
    case pkgimage::entry_type::character_device:
      if (!entry.device)
        return false;
      type = S_IFCHR;
      device = ::makedev(entry.device->major, entry.device->minor);
      break;
    case pkgimage::entry_type::block_device:
      if (!entry.device)
        return false;
      type = S_IFBLK;
      device = ::makedev(entry.device->major, entry.device->minor);
      break;
    default:
      return false;
  }
  if (::mknodat(workspace.parent_descriptor(),
                workspace.prepared_name().c_str(), type | 0600, device) != 0)
    return false;
  if (!apply_path_metadata(workspace.parent_descriptor(),
                           workspace.prepared_name(), entry, false))
  {
    remove_prepared(workspace, entry.type);
    return false;
  }
  return true;
}

[[nodiscard]] bool
directory_empty(int parent, const std::string& name)
{
  unique_fd directory(::openat(
      parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (directory.get() < 0)
    return false;
  DIR* stream = ::fdopendir(directory.release());
  if (stream == nullptr)
    return false;
  bool empty = true;
  errno = 0;
  while (dirent* entry = ::readdir(stream)) {
    if (std::strcmp(entry->d_name, ".") != 0 &&
        std::strcmp(entry->d_name, "..") != 0)
    {
      empty = false;
      break;
    }
  }
  const int saved = errno;
  static_cast<void>(::closedir(stream));
  if (saved != 0)
    return false;
  return empty;
}

[[nodiscard]] bool
prepare_hardlink_from(int source_parent,
                      const std::string& source_name,
                      const active_path_workspace& workspace)
{
  if (::linkat(source_parent, source_name.c_str(),
               workspace.parent_descriptor(),
               workspace.prepared_name().c_str(), 0) != 0)
    return false;
  const auto anchor_status = stat_leaf(source_parent, source_name);
  const auto prepared_status = stat_leaf(
      workspace.parent_descriptor(), workspace.prepared_name());
  if (!anchor_status || !prepared_status ||
      !S_ISREG(anchor_status->st_mode) ||
      anchor_status->st_dev != prepared_status->st_dev ||
      anchor_status->st_ino != prepared_status->st_ino)
  {
    remove_prepared(workspace, pkgimage::entry_type::hardlink);
    return false;
  }
  return true;
}

[[nodiscard]] bool
prepare_hardlink(const application_active_workspace& roots,
                 const active_path_workspace& workspace,
                 const pkgimage::package_entry& entry)
{
  if (!entry.hardlink_target)
    return false;
  active_path_workspace anchor = roots.open(
      pkgplan::package_path::parse(entry.hardlink_target->string()));
  return prepare_hardlink_from(
      anchor.parent_descriptor(), anchor.leaf(), workspace);
}

struct prepared_publication final {
  backend_operation_result result;
  int object_descriptor;
  int parent_descriptor;
};

[[nodiscard]] prepared_publication
publish_prepared(active_path_workspace& workspace,
                 const pkgimage::package_entry& entry,
                 unique_fd prepared_descriptor,
                 bool preserve_old)
{
  const auto final_status = stat_leaf(
      workspace.parent_descriptor(), workspace.leaf());
  const bool final_directory =
      final_status && S_ISDIR(final_status->st_mode);

  const bool incoming_directory =
      entry.type == pkgimage::entry_type::directory;
  const bool displace = final_status &&
      (final_directory != incoming_directory ||
       (preserve_old && !final_directory));
  if (displace) {
    if (final_directory &&
        !directory_empty(workspace.parent_descriptor(), workspace.leaf()))
    {
      remove_prepared(workspace, entry.type);
      return {operation(backend_operation_outcome::failed), -1, -1};
    }
    if (::renameat(workspace.parent_descriptor(), workspace.leaf().c_str(),
                   workspace.parent_descriptor(),
                   workspace.displaced_name().c_str()) != 0)
    {
      remove_prepared(workspace, entry.type);
      return {operation(backend_operation_outcome::failed), -1, -1};
    }
    if (final_directory &&
        !directory_empty(
            workspace.parent_descriptor(), workspace.displaced_name()))
    {
      const bool restored = ::renameat(
          workspace.parent_descriptor(), workspace.displaced_name().c_str(),
          workspace.parent_descriptor(), workspace.leaf().c_str()) == 0;
      remove_prepared(workspace, entry.type);
      return {operation(restored ? backend_operation_outcome::failed
                                 : backend_operation_outcome::indeterminate),
              -1, -1};
    }
  }

  if (::renameat(workspace.parent_descriptor(),
                 workspace.prepared_name().c_str(),
                 workspace.parent_descriptor(), workspace.leaf().c_str()) != 0)
  {
    const auto displaced = stat_leaf(
        workspace.parent_descriptor(), workspace.displaced_name());
    if (displaced) {
      static_cast<void>(::renameat(
          workspace.parent_descriptor(), workspace.displaced_name().c_str(),
          workspace.parent_descriptor(), workspace.leaf().c_str()));
    }
    remove_prepared(workspace, entry.type);
    return {operation(backend_operation_outcome::indeterminate), -1, -1};
  }

  return {operation(backend_operation_outcome::completed),
          prepared_descriptor.release(),
          duplicate_fd(workspace.parent_descriptor())};
}

[[nodiscard]] backend_operation_result
update_existing_directory(application_active_namespace& target,
                          active_path_workspace& workspace,
                          const pkgimage::package_entry& entry)
{
  unique_fd directory(::openat(
      workspace.parent_descriptor(), workspace.leaf().c_str(),
      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (directory.get() < 0)
    return operation(backend_operation_outcome::indeterminate);
  struct stat before {};
  if (::fstat(directory.get(), &before) != 0)
    return operation(backend_operation_outcome::indeterminate);

  const bool owner_matches =
      static_cast<std::uint64_t>(before.st_uid) == entry.uid &&
      static_cast<std::uint64_t>(before.st_gid) == entry.gid;
  const bool mode_matches =
      static_cast<std::uint32_t>(before.st_mode & 07777) ==
      (entry.mode & 07777U);
  const bool time_matches = before.st_mtim.tv_sec == entry.mtime &&
      static_cast<std::uint32_t>(before.st_mtim.tv_nsec) ==
      entry.mtime_nanoseconds;
  if (owner_matches && mode_matches && time_matches)
    return operation(backend_operation_outcome::completed);

  bool changed = false;
  if (!owner_matches) {
    if (::fchown(directory.get(), static_cast<uid_t>(entry.uid),
                 static_cast<gid_t>(entry.gid)) != 0)
      return operation(backend_operation_outcome::failed);
    changed = true;
  }
  if (!mode_matches) {
    if (::fchmod(
            directory.get(),
            static_cast<mode_t>(entry.mode & 07777U)) != 0)
      return operation(changed ? backend_operation_outcome::indeterminate
                               : backend_operation_outcome::failed);
    changed = true;
  }
  if (!time_matches) {
    const struct timespec times[2] = {
        {0, UTIME_OMIT},
        {entry.mtime, static_cast<long>(entry.mtime_nanoseconds)},
    };
    if (::futimens(directory.get(), times) != 0)
      return operation(changed ? backend_operation_outcome::indeterminate
                               : backend_operation_outcome::failed);
    changed = true;
  }
  if (changed)
    target.retain_dirty_descriptor(directory.release());
  return operation(backend_operation_outcome::completed);
}


template<class Value>
[[nodiscard]] const Value&
known_value(const qualified_fact<Value>& fact, const char* message)
{
  if (fact.state() != fact_state::known || !fact.value())
    throw std::logic_error(message);
  return *fact.value();
}

[[nodiscard]] bool
apply_captured_descriptor_metadata(
    int descriptor,
    const completed_object_fact& object)
{
  const auto mode = known_value(object.mode(), "capture lacks exact mode");
  const auto uid = known_value(object.uid(), "capture lacks exact uid");
  const auto gid = known_value(object.gid(), "capture lacks exact gid");
  const auto time = known_value(object.mtime(), "capture lacks exact mtime");
  if (::fchown(descriptor, static_cast<uid_t>(uid),
               static_cast<gid_t>(gid)) != 0)
    return false;
  if (::fchmod(descriptor, static_cast<mode_t>(mode & 07777U)) != 0)
    return false;
  const struct timespec times[2] = {
      {0, UTIME_OMIT},
      {time.seconds, static_cast<long>(time.nanoseconds)},
  };
  return ::futimens(descriptor, times) == 0;
}

[[nodiscard]] pkgimage::package_entry
captured_entry(const completed_object_fact& object)
{
  pkgimage::entry_type type = pkgimage::entry_type::directory;
  switch (object.kind()) {
    case completed_object_kind::directory:
      type = pkgimage::entry_type::directory;
      break;
    case completed_object_kind::symlink:
      type = pkgimage::entry_type::symlink;
      break;
    case completed_object_kind::fifo:
      type = pkgimage::entry_type::fifo;
      break;
    case completed_object_kind::character_device:
      type = pkgimage::entry_type::character_device;
      break;
    case completed_object_kind::block_device:
      type = pkgimage::entry_type::block_device;
      break;
    case completed_object_kind::regular:
    case completed_object_kind::socket:
    case completed_object_kind::other:
      throw std::logic_error("captured object has no metadata-only entry");
  }

  pkgimage::package_entry entry(
      pkgimage::package_path::parse(object.path().string()), type);
  entry.mode = known_value(object.mode(), "capture lacks exact mode");
  entry.uid = known_value(object.uid(), "capture lacks exact uid");
  entry.gid = known_value(object.gid(), "capture lacks exact gid");
  const auto time = known_value(object.mtime(), "capture lacks exact mtime");
  entry.mtime = time.seconds;
  entry.mtime_nanoseconds = time.nanoseconds;
  if (type == pkgimage::entry_type::symlink) {
    entry.symlink_target = known_value(
        object.symlink_target(), "capture lacks exact symlink target");
  }
  if (type == pkgimage::entry_type::character_device ||
      type == pkgimage::entry_type::block_device)
  {
    const auto device = known_value(
        object.device(), "capture lacks exact device number");
    entry.device = pkgimage::device_number{device.major, device.minor};
  }
  return entry;
}

[[nodiscard]] unique_fd
prepare_captured_regular(
    const active_path_workspace& workspace,
    const captured_old_object& captured,
    const completed_object_fact& object)
{
  captured_regular_object source = captured.open_regular();
  unique_fd file(::openat(
      workspace.parent_descriptor(), workspace.prepared_name().c_str(),
      O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (file.get() < 0)
    return unique_fd();
  try {
    const auto size = known_value(
        object.size(), "regular capture lacks exact size");
    const auto digest = copy_regular_payload(
        source.descriptor(), file.get(), size);
    const auto& expected = known_value(
        object.regular_content(),
        "regular capture lacks exact content identity");
    if (source.size() != size || digest != expected.bytes() ||
        !apply_captured_descriptor_metadata(file.get(), object))
    {
      static_cast<void>(::unlinkat(
          workspace.parent_descriptor(), workspace.prepared_name().c_str(), 0));
      return unique_fd();
    }
  } catch (...) {
    static_cast<void>(::unlinkat(
        workspace.parent_descriptor(), workspace.prepared_name().c_str(), 0));
    throw;
  }
  return file;
}

enum class leaf_removal : std::uint8_t {
  absent,
  removed,
  refused,
};

[[nodiscard]] leaf_removal
remove_leaf(int parent, const std::string& name)
{
  const auto status = stat_leaf(parent, name);
  if (!status)
    return leaf_removal::absent;
  if (S_ISDIR(status->st_mode) && !directory_empty(parent, name))
    return leaf_removal::refused;
  const int flags = S_ISDIR(status->st_mode) ? AT_REMOVEDIR : 0;
  if (::unlinkat(parent, name.c_str(), flags) == 0)
    return leaf_removal::removed;
  return errno == ENOENT ? leaf_removal::absent : leaf_removal::refused;
}

[[nodiscard]] completed_object_kind
incoming_kind(pkgimage::entry_type type)
{
  switch (type) {
    case pkgimage::entry_type::regular:
    case pkgimage::entry_type::hardlink:
      return completed_object_kind::regular;
    case pkgimage::entry_type::directory:
      return completed_object_kind::directory;
    case pkgimage::entry_type::symlink:
      return completed_object_kind::symlink;
    case pkgimage::entry_type::fifo:
      return completed_object_kind::fifo;
    case pkgimage::entry_type::character_device:
      return completed_object_kind::character_device;
    case pkgimage::entry_type::block_device:
      return completed_object_kind::block_device;
  }
  throw std::logic_error("invalid incoming object kind");
}

template<class Value>
[[nodiscard]] bool
matches_known(const qualified_fact<Value>& fact, const Value& expected)
{
  return fact.state() == fact_state::known && fact.value() &&
      *fact.value() == expected;
}

[[nodiscard]] bool
matches_incoming(
    int root_fd,
    const pkgplan::package_path& path,
    const pkgimage::package_entry& entry)
{
  application_target_observer observer =
      application_target_observer::from_directory_fd(root_fd);
  std::vector<pkgplan::package_path> paths {path};
  std::vector<target_hardlink_expectation> hardlinks;
  if (entry.type == pkgimage::entry_type::hardlink && entry.hardlink_target) {
    auto anchor =
        pkgplan::package_path::parse(entry.hardlink_target->string());
    paths.push_back(anchor);
    hardlinks.emplace_back(path, std::move(anchor));
  }
  backend_observation_batch batch = observer.observe(
      std::move(paths), std::move(hardlinks));
  const auto* observation = batch.find(path);
  if (observation == nullptr || observation->state() != fact_state::known ||
      !observation->object())
    return false;
  const auto& object = *observation->object();
  if (object.kind() != incoming_kind(entry.type) ||
      !matches_known(object.mode(), entry.mode) ||
      !matches_known(object.uid(), entry.uid) ||
      !matches_known(object.gid(), entry.gid) ||
      !matches_known(
          object.mtime(),
          completed_object_timestamp{
              entry.mtime, entry.mtime_nanoseconds}))
  {
    return false;
  }
  switch (entry.type) {
    case pkgimage::entry_type::regular:
      return entry.regular_content &&
          matches_known(object.size(), entry.size) &&
          object.regular_content().state() == fact_state::known &&
          object.regular_content().value() &&
          equal_digest_bytes(
              object.regular_content().value()->bytes(),
              entry.regular_content->bytes());
    case pkgimage::entry_type::directory:
    case pkgimage::entry_type::fifo:
      return true;
    case pkgimage::entry_type::symlink:
      return entry.symlink_target &&
          matches_known(object.symlink_target(), *entry.symlink_target);
    case pkgimage::entry_type::hardlink:
      return entry.hardlink_target &&
          object.hardlink().state() == fact_state::known &&
          object.hardlink().value() &&
          object.hardlink().value()->anchor().string() ==
              entry.hardlink_target->string();
    case pkgimage::entry_type::character_device:
    case pkgimage::entry_type::block_device:
      return entry.device &&
          matches_known(
              object.device(),
              completed_device_number{
                  entry.device->major, entry.device->minor});
  }
  return false;
}

struct recovery_preparation final {
  pkgimage::entry_type type;
  unique_fd descriptor;
  bool prepared_without_descriptor;
};

[[nodiscard]] recovery_preparation
prepare_capture(
    const application_active_workspace& roots,
    const active_path_workspace& workspace,
    const captured_old_object& captured)
{
  if (!captured.exact_recovery_possible() ||
      captured.observation().state() != fact_state::known ||
      !captured.observation().object())
  {
    throw std::invalid_argument(
        "old-object capture is not exact recovery authority");
  }
  const auto& object = *captured.observation().object();
  if (object.kind() == completed_object_kind::regular) {
    if (object.hardlink().state() == fact_state::known &&
        object.hardlink().value())
    {
      pkgimage::package_entry entry(
          pkgimage::package_path::parse(object.path().string()),
          pkgimage::entry_type::hardlink);
      entry.hardlink_target = pkgimage::package_path::parse(
          object.hardlink().value()->anchor().string());
      return {pkgimage::entry_type::hardlink, unique_fd(),
              prepare_hardlink(roots, workspace, entry)};
    }
    unique_fd regular = prepare_captured_regular(workspace, captured, object);
    return {pkgimage::entry_type::regular, std::move(regular), false};
  }

  pkgimage::package_entry entry = captured_entry(object);
  switch (entry.type) {
    case pkgimage::entry_type::directory: {
      unique_fd directory = prepare_directory(workspace, entry);
      return {entry.type, std::move(directory), false};
    }
    case pkgimage::entry_type::symlink:
      return {entry.type, unique_fd(), prepare_symlink(workspace, entry)};
    case pkgimage::entry_type::fifo:
    case pkgimage::entry_type::character_device:
    case pkgimage::entry_type::block_device:
      return {entry.type, unique_fd(), prepare_special(workspace, entry)};
    case pkgimage::entry_type::regular:
    case pkgimage::entry_type::hardlink:
      break;
  }
  throw std::logic_error("invalid captured recovery object kind");
}

[[nodiscard]] prepared_publication
publish_recovery(
    active_path_workspace& workspace,
    recovery_preparation prepared)
{
  if (prepared.descriptor.get() < 0 &&
      !prepared.prepared_without_descriptor)
  {
    return {operation(backend_operation_outcome::indeterminate), -1, -1};
  }

  const auto final = stat_leaf(
      workspace.parent_descriptor(), workspace.leaf());
  if (final && S_ISDIR(final->st_mode)) {
    if (!directory_empty(workspace.parent_descriptor(), workspace.leaf()) ||
        ::unlinkat(workspace.parent_descriptor(), workspace.leaf().c_str(),
                   AT_REMOVEDIR) != 0)
    {
      remove_prepared(workspace, prepared.type);
      return {operation(backend_operation_outcome::indeterminate), -1, -1};
    }
  }
  if (::renameat(workspace.parent_descriptor(),
                 workspace.prepared_name().c_str(),
                 workspace.parent_descriptor(), workspace.leaf().c_str()) != 0)
  {
    remove_prepared(workspace, prepared.type);
    return {operation(backend_operation_outcome::indeterminate), -1, -1};
  }
  return {operation(backend_operation_outcome::completed),
          prepared.descriptor.release(),
          duplicate_fd(workspace.parent_descriptor())};
}

} // namespace

application_active_namespace application_active_namespace::bind(
    int target_root_fd,
    application_attempt attempt,
    const pkgimage::package_image& incoming_image,
    const sealed_application_payloads* payloads,
    std::vector<application_path_observation> admitted,
    std::vector<captured_old_object> captures)
{
  application_active_workspace workspace =
      application_active_workspace::from_directory_fd(
          target_root_fd, std::move(attempt));
  validate_binding(workspace, incoming_image, payloads);
  validate_hard_links(incoming_image);
  normalize_admitted(admitted);
  validate_captures(workspace, admitted, captures);
  return application_active_namespace(
      std::move(workspace), &incoming_image, payloads, std::move(admitted),
      std::move(captures));
}

application_active_namespace
application_active_namespace::bind_without_incoming(
    int target_root_fd,
    application_attempt attempt,
    std::vector<application_path_observation> admitted,
    std::vector<captured_old_object> captures)
{
  application_active_workspace workspace =
      application_active_workspace::from_directory_fd(
          target_root_fd, std::move(attempt));
  normalize_admitted(admitted);
  validate_captures(workspace, admitted, captures);
  return application_active_namespace(
      std::move(workspace), nullptr, nullptr, std::move(admitted),
      std::move(captures));
}

application_active_namespace::application_active_namespace(
    application_active_workspace workspace,
    const pkgimage::package_image* incoming_image,
    const sealed_application_payloads* payloads,
    std::vector<application_path_observation> admitted,
    std::vector<captured_old_object> captures)
    : workspace_(std::move(workspace)), incoming_image_(incoming_image),
      payloads_(payloads), admitted_(std::move(admitted)),
      captures_(std::move(captures))
{
}

application_active_namespace::application_active_namespace(
    application_active_namespace&& other) noexcept
    : workspace_(std::move(other.workspace_)),
      incoming_image_(other.incoming_image_), payloads_(other.payloads_),
      admitted_(std::move(other.admitted_)),
      captures_(std::move(other.captures_)),
      effects_(std::move(other.effects_)),
      dirty_descriptors_(std::move(other.dirty_descriptors_))
{
  other.incoming_image_ = nullptr;
  other.payloads_ = nullptr;
  other.dirty_descriptors_.clear();
}

application_active_namespace& application_active_namespace::operator=(
    application_active_namespace&& other) noexcept
{
  if (this != &other) {
    for (int descriptor : dirty_descriptors_)
      static_cast<void>(::close(descriptor));
    workspace_ = std::move(other.workspace_);
    incoming_image_ = other.incoming_image_;
    payloads_ = other.payloads_;
    admitted_ = std::move(other.admitted_);
    captures_ = std::move(other.captures_);
    effects_ = std::move(other.effects_);
    dirty_descriptors_ = std::move(other.dirty_descriptors_);
    other.incoming_image_ = nullptr;
    other.payloads_ = nullptr;
    other.dirty_descriptors_.clear();
  }
  return *this;
}

application_active_namespace::~application_active_namespace()
{
  for (int descriptor : dirty_descriptors_)
    static_cast<void>(::close(descriptor));
}

const application_path_observation* application_active_namespace::admitted(
    const pkgplan::package_path& path) const noexcept
{
  const auto found = std::lower_bound(
      admitted_.begin(), admitted_.end(), path,
      [](const auto& observation, const auto& expected) {
        return observation.path() < expected;
      });
  return found != admitted_.end() && found->path() == path ? &*found : nullptr;
}

const captured_old_object* application_active_namespace::capture(
    const pkgplan::package_path& path) const noexcept
{
  const auto found = std::find_if(
      captures_.begin(), captures_.end(),
      [&path](const auto& value) {
        return value.request().path() == path;
      });
  return found == captures_.end() ? nullptr : &*found;
}

void application_active_namespace::retain_effect(
    const pkgplan::package_path& path,
    bool incoming)
{
  const auto found = std::find_if(
      effects_.begin(), effects_.end(),
      [&path](const auto& value) { return value.path == path; });
  if (found != effects_.end()) {
    if (found->incoming != incoming)
      throw std::logic_error("active path received contradictory effects");
    return;
  }
  effects_.push_back(attempted_effect{path, incoming});
}

void application_active_namespace::retain_completed_effect(
    const backend_active_effect_request& request,
    const backend_operation_result& result)
{
  const auto* before = admitted(request.path());
  if (before == nullptr)
    throw std::invalid_argument(
        "retained active effect lacks admitted observation");

  const bool incoming = request.outcome() ==
      pkgplan::planned_active_outcome::activate_incoming;
  const bool removal = request.outcome() ==
          pkgplan::planned_active_outcome::remove_observed ||
      request.outcome() ==
          pkgplan::planned_active_outcome::remove_directory_if_empty;
  if (!incoming && !removal)
    return;
  if (result.outcome() == backend_operation_outcome::failed ||
      result.outcome() == backend_operation_outcome::conditional_retained)
    return;
  if (result.outcome() == backend_operation_outcome::indeterminate) {
    retain_effect(request.path(), incoming);
    return;
  }

  active_path_workspace workspace = workspace_.open(request.path());
  const active_workspace_snapshot snapshot = workspace.inspect();
  if (snapshot.state() == active_workspace_state::contradictory)
    throw std::invalid_argument(
        "completed active effect has contradictory workspace authority");

  bool established = false;
  if (incoming) {
    if (incoming_image_ == nullptr || !request.incoming_entry())
      throw std::invalid_argument(
          "completed incoming effect lacks image authority");
    const auto* entry = incoming_image_->entry(*request.incoming_entry());
    established = entry != nullptr &&
        entry->path.string() == request.path().string() &&
        matches_incoming(
            workspace_.target_root_descriptor(), request.path(), *entry);
  }
  else {
    established = !stat_leaf(
        workspace.parent_descriptor(), workspace.leaf()).has_value();
  }
  if (!established)
    throw std::invalid_argument(
        "completed active effect is not visible in the selected target");
  retain_effect(request.path(), incoming);
}

void application_active_namespace::retain_dirty_descriptor(int descriptor)
{
  if (descriptor < 0)
    throw std::invalid_argument("invalid active durability descriptor");
  dirty_descriptors_.push_back(descriptor);
}

backend_operation_result application_active_namespace::publish_incoming(
    const backend_active_effect_request& request)
{
  if (incoming_image_ == nullptr)
    throw std::logic_error("active namespace has no incoming image");
  const auto& entry = resolve_entry(*incoming_image_, request);
  const auto* before = admitted(request.path());
  if (before == nullptr)
    throw std::invalid_argument("active request lacks admitted observation");

  active_path_workspace workspace = workspace_.open(request.path());
  if (workspace.inspect().state() != active_workspace_state::clear)
    return operation(backend_operation_outcome::failed);
  if (!still_admitted(workspace_, *before))
    return operation(backend_operation_outcome::indeterminate);
  retain_effect(request.path(), true);

  const auto current = stat_leaf(
      workspace.parent_descriptor(), workspace.leaf());
  if (entry.type == pkgimage::entry_type::directory && current &&
      S_ISDIR(current->st_mode))
  {
    return update_existing_directory(*this, workspace, entry);
  }

  unique_fd prepared;
  bool prepared_without_descriptor = false;
  switch (entry.type) {
    case pkgimage::entry_type::regular:
      prepared = prepare_regular(workspace, entry, payloads_);
      if (prepared.get() < 0)
        return operation(backend_operation_outcome::failed);
      break;
    case pkgimage::entry_type::directory:
      prepared = prepare_directory(workspace, entry);
      if (prepared.get() < 0)
        return operation(backend_operation_outcome::failed);
      break;
    case pkgimage::entry_type::symlink:
      prepared_without_descriptor = prepare_symlink(workspace, entry);
      break;
    case pkgimage::entry_type::hardlink:
      prepared_without_descriptor = prepare_hardlink(
          workspace_, workspace, entry);
      break;
    case pkgimage::entry_type::fifo:
    case pkgimage::entry_type::character_device:
    case pkgimage::entry_type::block_device:
      prepared_without_descriptor = prepare_special(workspace, entry);
      break;
  }
  if (prepared.get() < 0 && !prepared_without_descriptor)
    return operation(backend_operation_outcome::failed);
  prepared_publication published =
      publish_prepared(
          workspace, entry, std::move(prepared),
          capture(request.path()) != nullptr);
  if (published.object_descriptor >= 0)
    retain_dirty_descriptor(published.object_descriptor);
  if (published.parent_descriptor >= 0)
    retain_dirty_descriptor(published.parent_descriptor);
  return std::move(published.result);
}

backend_operation_result application_active_namespace::remove(
    const backend_active_effect_request& request)
{
  if (request.outcome() != pkgplan::planned_active_outcome::remove_observed &&
      request.outcome() !=
          pkgplan::planned_active_outcome::remove_directory_if_empty)
  {
    throw std::invalid_argument("active removal received another outcome");
  }
  if (request.incoming_entry())
    throw std::invalid_argument("active removal cites an incoming entry");

  const auto* before = admitted(request.path());
  if (before == nullptr || before->state() != fact_state::known ||
      !before->object())
  {
    throw std::invalid_argument("active removal lacks a present observation");
  }
  const bool directory = before->object()->kind() ==
      completed_object_kind::directory;
  if ((request.outcome() ==
           pkgplan::planned_active_outcome::remove_directory_if_empty) !=
      directory)
  {
    throw std::invalid_argument(
        "active removal outcome mismatches object kind");
  }

  active_path_workspace workspace = workspace_.open(request.path());
  if (workspace.inspect().state() != active_workspace_state::clear)
    return operation(backend_operation_outcome::indeterminate);
  if (!still_admitted(workspace_, *before))
    return operation(backend_operation_outcome::indeterminate);
  retain_effect(request.path(), false);

  int result = -1;
  if (capture(request.path()) != nullptr) {
    if (directory &&
        !directory_empty(workspace.parent_descriptor(), workspace.leaf()))
    {
      return operation(backend_operation_outcome::conditional_retained);
    }
    result = ::renameat(
        workspace.parent_descriptor(), workspace.leaf().c_str(),
        workspace.parent_descriptor(), workspace.displaced_name().c_str());
  } else {
    const int flags = directory ? AT_REMOVEDIR : 0;
    result = ::unlinkat(
        workspace.parent_descriptor(), workspace.leaf().c_str(), flags);
  }
  if (result == 0) {
    const int parent = duplicate_fd(workspace.parent_descriptor());
    if (parent >= 0)
      retain_dirty_descriptor(parent);
    return operation(backend_operation_outcome::completed);
  }

  const int failure = errno;
  const bool unchanged = still_admitted(workspace_, *before);
  if (!unchanged)
    return operation(backend_operation_outcome::indeterminate);
  if (directory && (failure == ENOTEMPTY || failure == EEXIST))
    return operation(backend_operation_outcome::conditional_retained);
  return operation(backend_operation_outcome::failed);
}

backend_operation_result application_active_namespace::recover(
    const pkgplan::package_path& path)
{
  const auto* before = admitted(path);
  if (before == nullptr)
    throw std::invalid_argument("active recovery lacks admitted observation");

  active_path_workspace workspace = workspace_.open(path);
  const active_workspace_snapshot snapshot = workspace.inspect();
  if (snapshot.state() == active_workspace_state::contradictory)
    return operation(backend_operation_outcome::indeterminate);

  if (snapshot.state() == active_workspace_state::prepared) {
    if (remove_leaf(
            workspace.parent_descriptor(), workspace.prepared_name()) ==
        leaf_removal::refused)
    {
      return operation(backend_operation_outcome::indeterminate);
    }
    return operation(
        still_admitted(workspace_, *before)
            ? backend_operation_outcome::completed
            : backend_operation_outcome::indeterminate);
  }

  if (snapshot.state() == active_workspace_state::displaced ||
      snapshot.state() ==
          active_workspace_state::removed_with_displaced_old ||
      snapshot.state() ==
          active_workspace_state::published_with_displaced_old)
  {
    if (remove_leaf(
            workspace.parent_descriptor(), workspace.prepared_name()) ==
        leaf_removal::refused)
    {
      return operation(backend_operation_outcome::indeterminate);
    }
    if (snapshot.final_present() &&
        remove_leaf(workspace.parent_descriptor(), workspace.leaf()) ==
            leaf_removal::refused)
    {
      return operation(backend_operation_outcome::indeterminate);
    }
    if (::renameat(
            workspace.parent_descriptor(),
            workspace.displaced_name().c_str(),
            workspace.parent_descriptor(), workspace.leaf().c_str()) != 0)
    {
      return operation(backend_operation_outcome::indeterminate);
    }
    const int parent = duplicate_fd(workspace.parent_descriptor());
    if (parent >= 0)
      retain_dirty_descriptor(parent);
    return operation(
        still_admitted(workspace_, *before)
            ? backend_operation_outcome::completed
            : backend_operation_outcome::indeterminate);
  }

  if (still_admitted(workspace_, *before))
    return operation(backend_operation_outcome::completed);

  const auto effect = std::find_if(
      effects_.begin(), effects_.end(),
      [&path](const auto& value) { return value.path == path; });
  if (effect == effects_.end())
    return operation(backend_operation_outcome::indeterminate);

  if (before->state() == fact_state::not_applicable) {
    if (!effect->incoming || incoming_image_ == nullptr)
      return operation(backend_operation_outcome::indeterminate);
    const auto* entry = incoming_image_->find(
        pkgimage::package_path::parse(path.string()));
    if (entry == nullptr ||
        !matches_incoming(
            workspace_.target_root_descriptor(), path, *entry))
    {
      return operation(backend_operation_outcome::indeterminate);
    }
    if (remove_leaf(workspace.parent_descriptor(), workspace.leaf()) ==
        leaf_removal::refused)
    {
      return operation(backend_operation_outcome::indeterminate);
    }
    const int parent = duplicate_fd(workspace.parent_descriptor());
    if (parent >= 0)
      retain_dirty_descriptor(parent);
    return operation(
        still_admitted(workspace_, *before)
            ? backend_operation_outcome::completed
            : backend_operation_outcome::indeterminate);
  }

  if (before->state() != fact_state::known || !before->object())
    return operation(backend_operation_outcome::indeterminate);
  const auto* captured = capture(path);
  if (captured == nullptr || !captured->exact_recovery_possible())
    return operation(backend_operation_outcome::indeterminate);

  const auto current = stat_leaf(
      workspace.parent_descriptor(), workspace.leaf());
  if (before->object()->kind() == completed_object_kind::directory &&
      current && S_ISDIR(current->st_mode))
  {
    pkgimage::package_entry directory = captured_entry(*before->object());
    backend_operation_result result = update_existing_directory(
        *this, workspace, directory);
    if (result.outcome() != backend_operation_outcome::completed)
      return result;
    return operation(
        still_admitted(workspace_, *before)
            ? backend_operation_outcome::completed
            : backend_operation_outcome::indeterminate);
  }

  recovery_preparation prepared = [&]() {
    if (before->object()->kind() != completed_object_kind::regular ||
        before->object()->hardlink().state() != fact_state::known ||
        !before->object()->hardlink().value())
    {
      return prepare_capture(workspace_, workspace, *captured);
    }

    const auto& anchor = before->object()->hardlink().value()->anchor();
    const auto* anchor_before = admitted(anchor);
    if (anchor_before == nullptr)
      return recovery_preparation{
          pkgimage::entry_type::hardlink, unique_fd(), false};
    if (still_admitted(workspace_, *anchor_before))
      return prepare_capture(workspace_, workspace, *captured);

    active_path_workspace anchor_workspace = workspace_.open(anchor);
    const active_workspace_snapshot anchor_snapshot =
        anchor_workspace.inspect();
    if (!anchor_snapshot.displaced_present() ||
        (anchor_snapshot.state() != active_workspace_state::displaced &&
         anchor_snapshot.state() !=
             active_workspace_state::published_with_displaced_old))
    {
      return recovery_preparation{
          pkgimage::entry_type::hardlink, unique_fd(), false};
    }
    return recovery_preparation{
        pkgimage::entry_type::hardlink, unique_fd(),
        prepare_hardlink_from(
            anchor_workspace.parent_descriptor(),
            anchor_workspace.displaced_name(), workspace)};
  }();
  prepared_publication published = publish_recovery(
      workspace, std::move(prepared));
  if (published.object_descriptor >= 0)
    retain_dirty_descriptor(published.object_descriptor);
  if (published.parent_descriptor >= 0)
    retain_dirty_descriptor(published.parent_descriptor);
  if (published.result.outcome() != backend_operation_outcome::completed)
    return published.result;
  return operation(
      still_admitted(workspace_, *before)
          ? backend_operation_outcome::completed
          : backend_operation_outcome::indeterminate);
}

backend_operation_result application_active_namespace::discard_recovery(
    const pkgplan::package_path& path)
{
  active_path_workspace workspace = workspace_.open(path);
  const active_workspace_snapshot before = workspace.inspect();
  if (before.state() == active_workspace_state::clear)
    return operation(backend_operation_outcome::completed);
  if (before.state() !=
          active_workspace_state::removed_with_displaced_old &&
      before.state() !=
          active_workspace_state::published_with_displaced_old)
  {
    return operation(backend_operation_outcome::indeterminate);
  }
  if (remove_leaf(
          workspace.parent_descriptor(), workspace.displaced_name()) !=
      leaf_removal::removed)
  {
    return operation(backend_operation_outcome::indeterminate);
  }
  const active_workspace_snapshot after = workspace.inspect();
  if (after.state() != active_workspace_state::clear ||
      after.final_present() != before.final_present())
  {
    return operation(backend_operation_outcome::indeterminate);
  }
  const int parent = duplicate_fd(workspace.parent_descriptor());
  if (parent >= 0)
    retain_dirty_descriptor(parent);
  return operation(backend_operation_outcome::completed);
}

application_durability_fact application_active_namespace::synchronize()
{
  for (int descriptor : dirty_descriptors_) {
    int result;
    do {
      result = ::fsync(descriptor);
    } while (result != 0 && errno == EINTR);
    if (result != 0) {
      return application_durability_fact(
          application_durability_domain::active_namespace,
          application_durability_status::unconfirmed);
    }
  }
  for (int descriptor : dirty_descriptors_)
    static_cast<void>(::close(descriptor));
  dirty_descriptors_.clear();
  return application_durability_fact(
      application_durability_domain::active_namespace,
      application_durability_status::confirmed);
}

} // namespace pkgapply::posix::detail
