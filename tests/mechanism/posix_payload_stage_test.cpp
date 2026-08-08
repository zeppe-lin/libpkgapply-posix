// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/payload_stage.h>
#include <libpkgimage/package_archive.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

void require(bool condition, std::string_view message)
{
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

class temporary_directory final {
public:
  temporary_directory()
  {
    std::array<char, 64> pattern{};
    const char* seed = "/tmp/libpkgapply-payload-stage-XXXXXX";
    std::memcpy(pattern.data(), seed, std::strlen(seed) + 1U);
    char* result = ::mkdtemp(pattern.data());
    if (result == nullptr) {
      std::cerr << "cannot create temporary directory: "
                << std::strerror(errno) << '\n';
      std::exit(1);
    }
    path_ = result;
  }

  ~temporary_directory()
  {
    const std::string command = "rm -rf -- '" + path_ + "'";
    static_cast<void>(std::system(command.c_str()));
  }

  const std::string& path() const noexcept { return path_; }

private:
  std::string path_;
};

std::array<std::uint8_t, 32> sha256(std::string_view bytes)
{
  std::array<std::uint8_t, 32> digest{};
  unsigned int size = 0;
  EVP_MD_CTX* context = EVP_MD_CTX_new();
  require(context != nullptr, "cannot allocate test digest context");
  require(EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1,
          "cannot initialize test digest");
  require(EVP_DigestUpdate(context, bytes.data(), bytes.size()) == 1,
          "cannot update test digest");
  require(EVP_DigestFinal_ex(context, digest.data(), &size) == 1 &&
              size == digest.size(),
          "cannot finalize test digest");
  EVP_MD_CTX_free(context);
  return digest;
}

pkgimage::package_entry regular(std::string path, std::string_view bytes)
{
  pkgimage::package_entry entry(
      pkgimage::package_path::parse(std::move(path)),
      pkgimage::entry_type::regular);
  entry.mode = 0644;
  entry.uid = 0;
  entry.gid = 0;
  entry.size = static_cast<std::uint64_t>(bytes.size());
  entry.regular_content =
      pkgimage::regular_content_digest::from_sha256(sha256(bytes));
  return entry;
}

class memory_archive final : public pkgimage::package_archive {
public:
  memory_archive(std::vector<pkgimage::package_entry> entries,
                 std::vector<std::string> payloads)
      : image_(std::move(entries)), payloads_(std::move(payloads)),
        receipt_(pkgimage::archive_backend_identity::parse(
                     "test/pkgimage-memory-v1"),
                 pkgimage::complete_archive_digest::from_sha256(sha256("archive")),
                 image_.identity(), image_.size())
  {
    require(image_.size() == payloads_.size(),
            "test archive payload count mismatch");
  }

  const pkgimage::package_image& image() const noexcept override
  {
    return image_;
  }

  const pkgimage::archive_inspection_receipt&
  inspection_receipt() const noexcept override
  {
    return receipt_;
  }

  void replay(const pkgimage::entry_selection& selection,
              pkgimage::payload_sink& sink) const override
  {
    selection.validate(image_);
    for (const auto& entry : image_.entries()) {
      if (!selection.contains(entry.id))
        continue;
      sink.begin(entry);
      const std::string& payload = payloads_.at(
          static_cast<std::size_t>(entry.id));
      if (!payload.empty()) {
        sink.write(
            entry, reinterpret_cast<const std::byte*>(payload.data()),
            payload.size());
      }
      sink.end(entry);
    }
  }

private:
  pkgimage::package_image image_;
  std::vector<std::string> payloads_;
  pkgimage::archive_inspection_receipt receipt_;
};

template<class Identity>
Identity application_identity(std::uint8_t seed)
{
  static constexpr char digits[] = "0123456789abcdef";
  std::string text = "v1:sha256:";
  for (std::size_t index = 0; index < 32U; ++index) {
    const auto byte = static_cast<std::uint8_t>(seed + index);
    text.push_back(digits[byte >> 4U]);
    text.push_back(digits[byte & 0x0fU]);
  }
  return Identity::parse(text);
}

pkgapply::application_attempt_nonce attempt_nonce(std::uint8_t seed)
{
  pkgapply::application_attempt_nonce::byte_array bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index)
    bytes[index] = static_cast<std::uint8_t>(seed + index);
  return pkgapply::application_attempt_nonce::from_bytes(bytes);
}

pkgapply::application_attempt attempt(std::uint8_t seed)
{
  return pkgapply::application_attempt::make(
      application_identity<pkgapply::application_request_identity>(seed),
      application_identity<pkgapply::application_target_context_identity>(
          static_cast<std::uint8_t>(seed + 1U)),
      application_identity<pkgapply::mutation_backend_identity>(
          static_cast<std::uint8_t>(seed + 2U)),
      attempt_nonce(static_cast<std::uint8_t>(seed + 3U)));
}

std::string stage_path(const std::string& root,
                       const pkgapply::application_attempt& value)
{
  const std::string identity = value.identity().string();
  return root + "/payload-v1-sha256-" +
      identity.substr(std::string("v1:sha256:").size());
}

std::string read_descriptor(int fd)
{
  std::string result;
  std::array<char, 64> buffer{};
  for (;;) {
    const ssize_t count = ::read(fd, buffer.data(), buffer.size());
    require(count >= 0, "cannot read staged payload descriptor");
    if (count == 0)
      break;
    result.append(buffer.data(), static_cast<std::size_t>(count));
  }
  return result;
}

void write_exact_file(const std::string& path, std::string_view bytes)
{
  const int fd = ::open(path.c_str(), O_WRONLY | O_TRUNC);
  require(fd >= 0, "cannot open staged payload for corruption test");
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count = ::write(fd, bytes.data() + offset,
                                  bytes.size() - offset);
    require(count > 0, "cannot corrupt staged payload");
    offset += static_cast<std::size_t>(count);
  }
  require(::close(fd) == 0, "cannot close corrupted staged payload");
}

} // namespace

int main()
{
  temporary_directory namespace_directory;
  memory_archive archive(
      {regular("usr/bin/tool", "abcd"), regular("usr/share/empty", "")},
      {"abcd", ""});
  const auto selection =
      pkgimage::entry_selection::all_regular(archive.image());
  const auto admitted_attempt = attempt(20);

  auto store = pkgapply::posix::application_payload_store::open(
      namespace_directory.path());
  {
    auto stage = store.begin(admitted_attempt, archive.image(), selection);
    archive.replay(selection, *stage);
    const auto result = stage->seal();
    require(result.outcome() == pkgapply::backend_operation_outcome::completed,
            "private payload stage did not seal");
    require(stage->sealed(), "private payload stage forgot successful seal");
  }

  auto loaded = store.load(admitted_attempt, archive.image(), selection);
  require(loaded.has_value(), "sealed payload stage was not restart-visible");
  require(loaded->attempt().identity() == admitted_attempt.identity(),
          "sealed payload stage changed application attempt");
  require(loaded->image() == archive.image().identity(),
          "sealed payload stage changed image identity");
  {
    auto payload = loaded->open(archive.image().entries().front().id);
    require(payload.size() == 4, "staged payload changed declared size");
    require(read_descriptor(payload.descriptor()) == "abcd",
            "staged payload changed bytes");
  }
  loaded.reset();

  // Replaying a durably sealed stage verifies bytes instead of rewriting it.
  {
    auto stage = store.begin(admitted_attempt, archive.image(), selection);
    archive.replay(selection, *stage);
    require(stage->seal().outcome() ==
                pkgapply::backend_operation_outcome::completed,
            "exact sealed payload replay was not idempotent");
  }

  bool foreign_binding = false;
  try {
    auto only_first = pkgimage::entry_selection::from_ids(
        archive.image(), {archive.image().entries().front().id});
    static_cast<void>(store.begin(admitted_attempt, archive.image(), only_first));
  } catch (const pkgapply::posix::payload_stage_error& error) {
    foreign_binding = error.code() ==
        pkgapply::posix::payload_stage_error_code::binding_mismatch;
  }
  require(foreign_binding,
          "private payload stage accepted another selection under one attempt");

  // An incomplete private stage is not restart authority and abandon removes it.
  const auto incomplete_attempt = attempt(70);
  {
    auto stage = store.begin(incomplete_attempt, archive.image(), selection);
    const auto& entry = archive.image().entries().front();
    stage->begin(entry);
    const std::string partial = "ab";
    stage->write(entry,
                 reinterpret_cast<const std::byte*>(partial.data()),
                 partial.size());
  }
  require(!store.load(incomplete_attempt, archive.image(), selection),
          "abandoned private payload stage became restart authority");

  // The retained namespace descriptor survives pathname movement.
  const std::string moved = namespace_directory.path() + ".moved";
  require(::rename(namespace_directory.path().c_str(), moved.c_str()) == 0,
          "cannot move payload staging namespace");
  require(store.load(admitted_attempt, archive.image(), selection).has_value(),
          "descriptor-anchored payload store followed the old pathname");
  require(::rename(moved.c_str(), namespace_directory.path().c_str()) == 0,
          "cannot restore payload staging namespace pathname");

  // A sealed file is revalidated before its descriptor is granted.
  const auto first_id = archive.image().entries().front().id;
  write_exact_file(
      stage_path(namespace_directory.path(), admitted_attempt) + "/entry-" +
          std::to_string(static_cast<std::uint64_t>(first_id)) + ".payload",
      "wxyz");
  bool corruption_rejected = false;
  try {
    auto corrupted = store.load(admitted_attempt, archive.image(), selection);
    require(corrupted.has_value(), "corrupted sealed stage disappeared");
    static_cast<void>(corrupted->open(first_id));
  } catch (const pkgapply::posix::payload_stage_error& error) {
    corruption_rejected = error.code() ==
        pkgapply::posix::payload_stage_error_code::entry_content_mismatch;
  }
  require(corruption_rejected,
          "sealed payload corruption survived descriptor validation");

  return 0;
}
