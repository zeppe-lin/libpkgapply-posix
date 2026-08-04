// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/rejected_store.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

namespace pkgapply::posix {
namespace {

constexpr std::array<std::byte, 8> binding_magic{
    std::byte{'Z'}, std::byte{'P'}, std::byte{'L'}, std::byte{'R'},
    std::byte{'J'}, std::byte{'B'}, std::byte{'N'}, std::byte{'D'}};
constexpr std::array<std::byte, 8> record_magic{
    std::byte{'Z'}, std::byte{'P'}, std::byte{'L'}, std::byte{'R'},
    std::byte{'J'}, std::byte{'O'}, std::byte{'B'}, std::byte{'J'}};
constexpr std::uint16_t binding_encoding_version = 1;
constexpr std::uint16_t rejected_record_encoding_version = 2;
constexpr std::size_t maximum_record_size = 4U * 1024U * 1024U;
constexpr mode_t private_directory_mode = 0700;
constexpr mode_t private_file_mode = 0600;

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

struct rejected_record final {
  application_attempt attempt;
  pkgplan::operation_plan_identity plan;
  backend_rejected_effect_request request;
  rejected_object_source source;
  application_path_observation observation;
  rejected_object_record_identity identity;
};

[[noreturn]] void
throw_error(rejected_store_error_code code,
            int system_error,
            std::string path,
            std::string message)
{
  throw rejected_store_error(
      code, system_error, std::move(path), std::move(message));
}

void
set_close_on_exec(int fd, rejected_store_error_code code)
{
  const int flags = ::fcntl(fd, F_GETFD);
  if (flags < 0 || ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0)
    throw_error(code, errno, {}, "cannot set close-on-exec flag");
}

int
open_path(const char* path, int flags)
{
  for (;;) {
    const int result = ::open(path, flags);
    if (result >= 0 || errno != EINTR)
      return result;
  }
}

int
open_at(int directory_fd, const char* path, int flags, mode_t mode = 0)
{
  for (;;) {
    const int result = mode == 0
        ? ::openat(directory_fd, path, flags)
        : ::openat(directory_fd, path, flags, mode);
    if (result >= 0 || errno != EINTR)
      return result;
  }
}

int
duplicate_fd(int fd, rejected_store_error_code code, const char* message)
{
#ifdef F_DUPFD_CLOEXEC
  const int duplicate = ::fcntl(fd, F_DUPFD_CLOEXEC, 0);
#else
  const int duplicate = ::dup(fd);
#endif
  if (duplicate < 0)
    throw_error(code, errno, {}, message);
  set_close_on_exec(duplicate, code);
  return duplicate;
}

void
require_directory(int fd,
                  rejected_store_error_code code,
                  const char* message)
{
  struct stat status {};
  if (::fstat(fd, &status) != 0)
    throw_error(code, errno, {}, message);
  if (!S_ISDIR(status.st_mode))
    throw_error(code, ENOTDIR, {}, message);
}

void
synchronize_fd(int fd,
               rejected_store_error_code code,
               const char* message)
{
  for (;;) {
    if (::fsync(fd) == 0)
      return;
    if (errno != EINTR)
      throw_error(code, errno, {}, message);
  }
}

void
write_all(int fd,
          const std::byte* data,
          std::size_t size,
          rejected_store_error_code code,
          const char* message)
{
  std::size_t offset = 0;
  while (offset < size) {
    const ssize_t count = ::write(fd, data + offset, size - offset);
    if (count < 0) {
      if (errno == EINTR)
        continue;
      throw_error(code, errno, {}, message);
    }
    if (count == 0)
      throw_error(code, EIO, {}, message);
    offset += static_cast<std::size_t>(count);
  }
}

void
write_all(int fd,
          const std::vector<std::byte>& bytes,
          rejected_store_error_code code,
          const char* message)
{
  write_all(fd, bytes.data(), bytes.size(), code, message);
}

std::vector<std::byte>
read_file(int directory_fd,
          const std::string& name,
          rejected_store_error_code open_code,
          rejected_store_error_code read_code,
          std::size_t maximum,
          bool absent_is_empty = false)
{
  unique_fd file(open_at(
      directory_fd, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (file.get() < 0) {
    if (absent_is_empty && errno == ENOENT)
      return {};
    throw_error(open_code, errno, name, "cannot open rejected-object record");
  }

  struct stat status {};
  if (::fstat(file.get(), &status) != 0)
    throw_error(read_code, errno, name, "cannot inspect rejected-object record");
  if (!S_ISREG(status.st_mode) || status.st_size < 0 ||
      static_cast<std::uint64_t>(status.st_size) > maximum)
  {
    throw_error(read_code, EINVAL, name,
                "rejected-object record has invalid type or size");
  }

  std::vector<std::byte> bytes(static_cast<std::size_t>(status.st_size));
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count = ::read(
        file.get(), bytes.data() + offset, bytes.size() - offset);
    if (count < 0) {
      if (errno == EINTR)
        continue;
      throw_error(read_code, errno, name, "cannot read rejected-object record");
    }
    if (count == 0)
      throw_error(read_code, EIO, name,
                  "rejected-object record was truncated while reading");
    offset += static_cast<std::size_t>(count);
  }
  std::byte probe{};
  for (;;) {
    const ssize_t count = ::read(file.get(), &probe, 1);
    if (count < 0 && errno == EINTR)
      continue;
    if (count < 0)
      throw_error(read_code, errno, name,
                  "cannot finish reading rejected-object record");
    if (count != 0)
      throw_error(read_code, EIO, name,
                  "rejected-object record changed size while reading");
    break;
  }
  return bytes;
}

std::string
hexadecimal(const std::uint8_t* bytes, std::size_t size)
{
  static constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(size * 2U);
  for (std::size_t index = 0; index < size; ++index) {
    result.push_back(digits[bytes[index] >> 4U]);
    result.push_back(digits[bytes[index] & 0x0fU]);
  }
  return result;
}

std::array<std::uint8_t, 32>
sha256_bytes(const std::byte* data, std::size_t size)
{
  std::unique_ptr<EVP_MD_CTX, evp_context_deleter> context(EVP_MD_CTX_new());
  if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
      (size != 0 && EVP_DigestUpdate(context.get(), data, size) != 1))
  {
    throw_error(rejected_store_error_code::record_invalid, EIO, {},
                "cannot calculate rejected-object digest");
  }
  std::array<std::uint8_t, 32> digest{};
  unsigned int digest_size = 0;
  if (EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) != 1 ||
      digest_size != digest.size())
  {
    throw_error(rejected_store_error_code::record_invalid, EIO, {},
                "cannot finalize rejected-object digest");
  }
  return digest;
}

std::array<std::uint8_t, 32>
sha256_text(std::string_view text)
{
  return sha256_bytes(
      reinterpret_cast<const std::byte*>(text.data()), text.size());
}

std::string
digest_text(const std::array<std::uint8_t, 32>& digest)
{
  return "v1:sha256:" + hexadecimal(digest.data(), digest.size());
}

void append_u8(std::vector<std::byte>& bytes, std::uint8_t value)
{
  bytes.push_back(static_cast<std::byte>(value));
}

void append_u16(std::vector<std::byte>& bytes, std::uint16_t value)
{
  append_u8(bytes, static_cast<std::uint8_t>((value >> 8U) & 0xffU));
  append_u8(bytes, static_cast<std::uint8_t>(value & 0xffU));
}

void append_u32(std::vector<std::byte>& bytes, std::uint32_t value)
{
  for (int shift = 24; shift >= 0; shift -= 8)
    append_u8(bytes, static_cast<std::uint8_t>((value >> shift) & 0xffU));
}

void append_u64(std::vector<std::byte>& bytes, std::uint64_t value)
{
  for (int shift = 56; shift >= 0; shift -= 8)
    append_u8(bytes, static_cast<std::uint8_t>((value >> shift) & 0xffU));
}

void append_i64(std::vector<std::byte>& bytes, std::int64_t value)
{
  const bool negative = value < 0;
  const std::uint64_t magnitude = negative
      ? static_cast<std::uint64_t>(-(value + 1)) + 1U
      : static_cast<std::uint64_t>(value);
  append_u8(bytes, negative ? 1U : 0U);
  append_u64(bytes, magnitude);
}

void append_string(std::vector<std::byte>& bytes, const std::string& value)
{
  if (value.size() > std::numeric_limits<std::uint32_t>::max())
    throw_error(rejected_store_error_code::record_invalid, EOVERFLOW, {},
                "rejected-object string is too large");
  append_u32(bytes, static_cast<std::uint32_t>(value.size()));
  bytes.insert(bytes.end(),
               reinterpret_cast<const std::byte*>(value.data()),
               reinterpret_cast<const std::byte*>(value.data() + value.size()));
}

class byte_reader final {
public:
  explicit byte_reader(const std::vector<std::byte>& bytes) : bytes_(bytes) {}

  [[nodiscard]] std::uint8_t u8()
  {
    require(1U);
    return std::to_integer<std::uint8_t>(bytes_[offset_++]);
  }
  [[nodiscard]] std::uint16_t u16()
  {
    std::uint16_t value = 0;
    for (int index = 0; index < 2; ++index)
      value = static_cast<std::uint16_t>((value << 8U) | u8());
    return value;
  }
  [[nodiscard]] std::uint32_t u32()
  {
    std::uint32_t value = 0;
    for (int index = 0; index < 4; ++index)
      value = (value << 8U) | u8();
    return value;
  }
  [[nodiscard]] std::uint64_t u64()
  {
    std::uint64_t value = 0;
    for (int index = 0; index < 8; ++index)
      value = (value << 8U) | u8();
    return value;
  }
  [[nodiscard]] std::int64_t i64()
  {
    const std::uint8_t sign = u8();
    if (sign > 1U)
      invalid("invalid signed value");
    const std::uint64_t magnitude = u64();
    if (sign == 0U) {
      if (magnitude > static_cast<std::uint64_t>(
              std::numeric_limits<std::int64_t>::max()))
        invalid("signed value is out of range");
      return static_cast<std::int64_t>(magnitude);
    }
    const std::uint64_t limit = static_cast<std::uint64_t>(
        std::numeric_limits<std::int64_t>::max()) + 1U;
    if (magnitude > limit)
      invalid("signed value is out of range");
    if (magnitude == limit)
      return std::numeric_limits<std::int64_t>::min();
    return -static_cast<std::int64_t>(magnitude);
  }
  [[nodiscard]] std::string string()
  {
    const std::uint32_t size = u32();
    require(size);
    const char* begin = reinterpret_cast<const char*>(bytes_.data() + offset_);
    std::string value(begin, begin + size);
    offset_ += size;
    return value;
  }
  [[nodiscard]] std::vector<std::byte> bytes(std::size_t size)
  {
    require(size);
    std::vector<std::byte> value(
        bytes_.begin() + static_cast<std::ptrdiff_t>(offset_),
        bytes_.begin() + static_cast<std::ptrdiff_t>(offset_ + size));
    offset_ += size;
    return value;
  }
  void finish()
  {
    if (offset_ != bytes_.size())
      invalid("rejected-object record contains trailing data");
  }
private:
  [[noreturn]] static void invalid(const char* message)
  {
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {}, message);
  }
  void require(std::size_t size)
  {
    if (size > bytes_.size() - offset_)
      invalid("rejected-object record is truncated");
  }
  const std::vector<std::byte>& bytes_;
  std::size_t offset_ = 0;
};

std::vector<std::byte>
frame(const std::array<std::byte, 8>& magic,
      std::uint16_t version,
      const std::vector<std::byte>& body)
{
  const auto checksum = sha256_bytes(body.data(), body.size());
  std::vector<std::byte> bytes;
  bytes.reserve(magic.size() + 2U + 8U + checksum.size() + body.size());
  bytes.insert(bytes.end(), magic.begin(), magic.end());
  append_u16(bytes, version);
  append_u64(bytes, body.size());
  for (const std::uint8_t byte : checksum)
    append_u8(bytes, byte);
  bytes.insert(bytes.end(), body.begin(), body.end());
  return bytes;
}

std::vector<std::byte>
unframe(const std::vector<std::byte>& bytes,
        const std::array<std::byte, 8>& magic,
        std::uint16_t version)
{
  constexpr std::size_t envelope = 8U + 2U + 8U + 32U;
  if (bytes.size() < envelope)
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
                "rejected-object record is truncated");
  byte_reader reader(bytes);
  const auto observed_magic = reader.bytes(magic.size());
  if (!std::equal(observed_magic.begin(), observed_magic.end(), magic.begin()))
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
                "rejected-object record has invalid magic");
  if (reader.u16() != version)
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
                "rejected-object record has unsupported version");
  const std::uint64_t body_size = reader.u64();
  if (body_size > maximum_record_size || body_size > bytes.size() - envelope ||
      body_size != bytes.size() - envelope)
  {
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
                "rejected-object record is truncated or oversized");
  }
  const auto expected_checksum = reader.bytes(32U);
  const auto body = reader.bytes(static_cast<std::size_t>(body_size));
  reader.finish();
  const auto checksum = sha256_bytes(body.data(), body.size());
  if (!std::equal(expected_checksum.begin(), expected_checksum.end(),
                  reinterpret_cast<const std::byte*>(checksum.data())))
  {
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
                "rejected-object record checksum mismatch");
  }
  return body;
}

std::vector<std::byte>
encode_attempt_body(const application_attempt& attempt)
{
  std::vector<std::byte> body;
  append_string(body, attempt.identity().string());
  append_string(body, attempt.request().string());
  append_string(body, attempt.target().string());
  append_string(body, attempt.backend().string());
  for (const std::uint8_t byte : attempt.nonce().bytes())
    append_u8(body, byte);
  return body;
}

void
require_attempt_body(byte_reader& reader, const application_attempt& attempt)
{
  if (reader.string() != attempt.identity().string() ||
      reader.string() != attempt.request().string() ||
      reader.string() != attempt.target().string() ||
      reader.string() != attempt.backend().string())
  {
    throw_error(rejected_store_error_code::binding_mismatch, EINVAL, {},
                "rejected-object attempt binding mismatch");
  }
  application_attempt_nonce::byte_array nonce{};
  for (auto& byte : nonce)
    byte = reader.u8();
  if (application_attempt_nonce::from_bytes(nonce) != attempt.nonce())
    throw_error(rejected_store_error_code::binding_mismatch, EINVAL, {},
                "rejected-object attempt nonce mismatch");
}

template<class Value, class Encoder>
void
append_fact(std::vector<std::byte>& body,
            const qualified_fact<Value>& fact,
            Encoder encode)
{
  append_u8(body, static_cast<std::uint8_t>(fact.state()));
  if (fact.state() == fact_state::known)
    encode(*fact.value());
}

fact_state
read_fact_state(byte_reader& reader)
{
  const auto value = reader.u8();
  if (value < static_cast<std::uint8_t>(fact_state::known) ||
      value > static_cast<std::uint8_t>(fact_state::not_applicable))
  {
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
                "rejected-object record has invalid fact state");
  }
  return static_cast<fact_state>(value);
}

template<class Value, class Decoder>
qualified_fact<Value>
read_fact(byte_reader& reader, Decoder decode)
{
  switch (read_fact_state(reader)) {
    case fact_state::known:
      return qualified_fact<Value>::known(decode());
    case fact_state::unknown:
      return qualified_fact<Value>::unknown();
    case fact_state::not_applicable:
      return qualified_fact<Value>::not_applicable();
  }
  throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
              "rejected-object record has invalid fact state");
}

void
append_observation(std::vector<std::byte>& body,
                   const application_path_observation& observation)
{
  append_string(body, observation.path().string());
  append_u8(body, static_cast<std::uint8_t>(observation.state()));
  if (observation.state() != fact_state::known || !observation.object())
    return;
  const auto& object = *observation.object();
  append_u8(body, static_cast<std::uint8_t>(object.kind()));
  append_u8(body, static_cast<std::uint8_t>(object.provenance()));
  append_u8(body, static_cast<std::uint8_t>(object.completeness()));
  append_fact(body, object.mode(), [&body](std::uint32_t value) {
    append_u32(body, value);
  });
  append_fact(body, object.uid(), [&body](std::uint64_t value) {
    append_u64(body, value);
  });
  append_fact(body, object.gid(), [&body](std::uint64_t value) {
    append_u64(body, value);
  });
  append_fact(body, object.size(), [&body](std::uint64_t value) {
    append_u64(body, value);
  });
  append_fact(body, object.mtime(), [&body](const auto& value) {
    append_i64(body, value.seconds);
    append_u32(body, value.nanoseconds);
  });
  append_fact(body, object.regular_content(), [&body](const auto& value) {
    append_string(body, value.string());
  });
  append_fact(body, object.symlink_target(), [&body](const auto& value) {
    append_string(body, value);
  });
  append_fact(body, object.device(), [&body](const auto& value) {
    append_u64(body, value.major);
    append_u64(body, value.minor);
  });
  append_fact(body, object.hardlink(), [&body](const auto& value) {
    append_string(body, value.anchor().string());
  });
}

application_path_observation
read_observation(byte_reader& reader)
{
  auto path = pkgplan::package_path::parse(reader.string());
  const auto state_value = reader.u8();
  if (state_value == static_cast<std::uint8_t>(fact_state::unknown))
    return application_path_observation::unknown(std::move(path));
  if (state_value == static_cast<std::uint8_t>(fact_state::not_applicable))
    return application_path_observation::absent(std::move(path));
  if (state_value != static_cast<std::uint8_t>(fact_state::known))
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
                "rejected-object record has invalid observation state");

  const auto kind_value = reader.u8();
  if (kind_value < static_cast<std::uint8_t>(completed_object_kind::regular) ||
      kind_value > static_cast<std::uint8_t>(completed_object_kind::other))
  {
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
                "rejected-object record has invalid object kind");
  }
  const auto provenance_value = reader.u8();
  if (provenance_value <
          static_cast<std::uint8_t>(object_fact_provenance::incoming_image) ||
      provenance_value >
          static_cast<std::uint8_t>(object_fact_provenance::rejected_capture))
  {
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
                "rejected-object record has invalid provenance");
  }
  const auto completeness_value = reader.u8();
  if (completeness_value <
          static_cast<std::uint8_t>(object_fact_completeness::complete) ||
      completeness_value >
          static_cast<std::uint8_t>(object_fact_completeness::partial))
  {
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
                "rejected-object record has invalid completeness");
  }

  auto mode = read_fact<std::uint32_t>(reader, [&reader] { return reader.u32(); });
  auto uid = read_fact<std::uint64_t>(reader, [&reader] { return reader.u64(); });
  auto gid = read_fact<std::uint64_t>(reader, [&reader] { return reader.u64(); });
  auto size = read_fact<std::uint64_t>(reader, [&reader] { return reader.u64(); });
  auto mtime = read_fact<completed_object_timestamp>(reader, [&reader] {
    return completed_object_timestamp{reader.i64(), reader.u32()};
  });
  auto content = read_fact<completed_regular_content_identity>(reader, [&reader] {
    return completed_regular_content_identity::parse(reader.string());
  });
  auto symlink = read_fact<std::string>(reader, [&reader] {
    return reader.string();
  });
  auto device = read_fact<completed_device_number>(reader, [&reader] {
    return completed_device_number{reader.u64(), reader.u64()};
  });
  auto hardlink = read_fact<completed_hardlink_relation>(reader, [&reader] {
    return completed_hardlink_relation(
        pkgplan::package_path::parse(reader.string()));
  });

  return application_path_observation::present(completed_object_fact(
      std::move(path), static_cast<completed_object_kind>(kind_value),
      std::move(mode), std::move(uid), std::move(gid), std::move(size),
      std::move(mtime), std::move(content), std::move(symlink),
      std::move(device), std::move(hardlink),
      static_cast<object_fact_provenance>(provenance_value),
      static_cast<object_fact_completeness>(completeness_value)));
}

std::vector<std::byte>
encode_binding(const application_attempt& attempt,
               const pkgplan::operation_plan_identity& plan)
{
  auto body = encode_attempt_body(attempt);
  append_string(body, plan.string());
  return frame(binding_magic, binding_encoding_version, body);
}

pkgplan::operation_plan_identity
decode_binding(const std::vector<std::byte>& bytes,
               const application_attempt& attempt)
{
  try {
    const auto body = unframe(bytes, binding_magic, binding_encoding_version);
    byte_reader reader(body);
    require_attempt_body(reader, attempt);
    const auto plan = pkgplan::operation_plan_identity::parse(reader.string());
    reader.finish();
    return plan;
  } catch (const rejected_store_error& error) {
    if (error.code() != rejected_store_error_code::record_invalid)
      throw;
    throw_error(rejected_store_error_code::binding_mismatch,
                error.system_error(), error.path(),
                "rejected-object attempt binding is corrupt");
  } catch (const std::invalid_argument&) {
    throw_error(rejected_store_error_code::binding_mismatch, EINVAL, {},
                "rejected-object attempt binding is corrupt");
  }
}

rejected_object_record_identity
record_identity(const std::vector<std::byte>& body)
{
  std::vector<std::byte> canonical;
  append_string(canonical,
                std::string(rejected_object_record_identity::canonical_domain()));
  canonical.insert(canonical.end(), body.begin(), body.end());
  return rejected_object_record_identity::parse(
      digest_text(sha256_bytes(canonical.data(), canonical.size())));
}

application_backend_evidence_identity
record_evidence(const std::vector<std::byte>& bytes)
{
  std::vector<std::byte> canonical;
  append_string(canonical,
                std::string(application_backend_evidence_identity::canonical_domain()));
  canonical.insert(canonical.end(), bytes.begin(), bytes.end());
  return application_backend_evidence_identity::parse(
      digest_text(sha256_bytes(canonical.data(), canonical.size())));
}

std::vector<std::byte>
encode_record_body(const application_attempt& attempt,
                   const pkgplan::operation_plan_identity& plan,
                   const backend_rejected_effect_request& request,
                   rejected_object_source source,
                   const application_path_observation& observation)
{
  const rejected_object_source expected_source =
      request.source_side() == pkgplan::rejected_object_source_side::incoming
          ? rejected_object_source::incoming
          : rejected_object_source::old;
  if (source != expected_source)
    throw std::invalid_argument(
        "rejected-object physical source differs from plan provenance");

  std::vector<std::byte> body = encode_attempt_body(attempt);
  append_string(body, plan.string());
  append_u8(body, static_cast<std::uint8_t>(request.source_side()));
  append_u8(body, static_cast<std::uint8_t>(request.reason()));
  append_string(body, request.path().string());
  append_string(body, request.release().string());
  append_string(body, request.observations().string());

  if (request.source_side() ==
      pkgplan::rejected_object_source_side::incoming)
  {
    append_string(body, request.artifact()->string());
    append_string(body, request.artifact_manifest()->string());
    append_string(body, request.image()->string());
    append_u64(body, static_cast<std::uint64_t>(*request.incoming_entry()));
  }
  else
  {
    append_string(body, request.installed_package()->string());
    append_string(body, request.installed_control()->string());
  }
  append_observation(body, observation);
  return body;
}

rejected_record
decode_record_unchecked(
    const std::vector<std::byte>& bytes,
    const application_attempt& attempt,
    const pkgplan::operation_plan_identity& expected_plan,
    const backend_rejected_effect_request& expected_request)
{
  const auto body = unframe(
      bytes, record_magic, rejected_record_encoding_version);
  byte_reader reader(body);
  require_attempt_body(reader, attempt);
  const auto plan = pkgplan::operation_plan_identity::parse(reader.string());
  if (plan != expected_plan)
    throw_error(rejected_store_error_code::binding_mismatch, EINVAL, {},
                "rejected-object plan binding mismatch");

  const auto source_value = reader.u8();
  if (source_value < static_cast<std::uint8_t>(
                         pkgplan::rejected_object_source_side::incoming) ||
      source_value > static_cast<std::uint8_t>(
                         pkgplan::rejected_object_source_side::old_installed))
  {
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
                "rejected-object record has invalid source side");
  }
  const auto source_side =
      static_cast<pkgplan::rejected_object_source_side>(source_value);

  const auto reason_value = reader.u8();
  if (reason_value < static_cast<std::uint8_t>(
                         pkgplan::rejected_object_reason::install_policy_exclusion) ||
      reason_value > static_cast<std::uint8_t>(
                         pkgplan::rejected_object_reason::removal_old_preservation))
  {
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
                "rejected-object record has invalid reason");
  }
  const auto reason = static_cast<pkgplan::rejected_object_reason>(reason_value);
  auto path = pkgplan::package_path::parse(reader.string());
  const auto release = pkgplan::package_release_identity::parse(reader.string());
  const auto observations =
      pkgplan::observation_set_identity::parse(reader.string());

  std::optional<pkgplan::artifact_identity> artifact;
  std::optional<pkgplan::artifact_manifest_identity> artifact_manifest;
  std::optional<pkgimage::package_image_identity> image;
  std::optional<pkgimage::entry_id> entry;
  std::optional<pkgplan::installed_package_identity> installed_package;
  std::optional<pkgplan::installed_control_identity> installed_control;

  if (source_side == pkgplan::rejected_object_source_side::incoming) {
    artifact = pkgplan::artifact_identity::parse(reader.string());
    artifact_manifest =
        pkgplan::artifact_manifest_identity::parse(reader.string());
    image = pkgimage::package_image_identity::parse(reader.string());
    const auto value = reader.u64();
    if (value > std::numeric_limits<pkgimage::entry_id>::max())
      throw_error(rejected_store_error_code::record_invalid, EOVERFLOW, {},
                  "rejected-object entry identity is out of range");
    entry = static_cast<pkgimage::entry_id>(value);
  }
  else {
    installed_package =
        pkgplan::installed_package_identity::parse(reader.string());
    installed_control =
        pkgplan::installed_control_identity::parse(reader.string());
  }

  auto observation = read_observation(reader);
  reader.finish();

  if (path != expected_request.path() ||
      source_side != expected_request.source_side() ||
      reason != expected_request.reason() ||
      release != expected_request.release() ||
      observations != expected_request.observations() ||
      artifact != expected_request.artifact() ||
      artifact_manifest != expected_request.artifact_manifest() ||
      image != expected_request.image() ||
      entry != expected_request.incoming_entry() ||
      installed_package != expected_request.installed_package() ||
      installed_control != expected_request.installed_control())
  {
    throw_error(rejected_store_error_code::binding_mismatch, EINVAL,
                expected_request.path().string(),
                "rejected-object structured provenance mismatch");
  }
  if (observation.path() != path || observation.state() != fact_state::known ||
      !observation.object())
  {
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
                "rejected-object observation binding is invalid");
  }

  const rejected_object_source source =
      expected_request.source_side() ==
              pkgplan::rejected_object_source_side::incoming
          ? rejected_object_source::incoming
          : rejected_object_source::old;
  return rejected_record{
      attempt, plan, expected_request, source, std::move(observation),
      record_identity(body)};
}

rejected_record
decode_record(const std::vector<std::byte>& bytes,
              const application_attempt& attempt,
              const pkgplan::operation_plan_identity& expected_plan,
              const backend_rejected_effect_request& expected_request)
{
  try {
    return decode_record_unchecked(
        bytes, attempt, expected_plan, expected_request);
  } catch (const rejected_store_error&) {
    throw;
  } catch (const std::invalid_argument&) {
    throw_error(rejected_store_error_code::record_invalid, EINVAL, {},
                "rejected-object record contains invalid canonical values");
  }
}

std::string
attempt_directory_name(const application_attempt& attempt)
{
  return "rejected-v1-" + hexadecimal(
      attempt.identity().bytes().data(), attempt.identity().bytes().size());
}

std::string
path_key(const pkgplan::package_path& path)
{
  const auto digest = sha256_text(path.string());
  return hexadecimal(digest.data(), digest.size());
}

std::string record_name(const pkgplan::package_path& path)
{
  return "record-v1-" + path_key(path);
}

std::string payload_name(const pkgplan::package_path& path)
{
  return "payload-v1-" + path_key(path);
}

const char* source_directory_name(rejected_object_source source)
{
  switch (source) {
    case rejected_object_source::incoming:
      return "incoming-v1";
    case rejected_object_source::old:
      return "old-v1";
  }
  throw std::logic_error("invalid rejected-object source");
}

std::string
temporary_name(std::string_view prefix)
{
  static std::atomic<std::uint64_t> sequence{0};
  const std::uint64_t current =
      sequence.fetch_add(1U, std::memory_order_relaxed) + 1U;
  return "." + std::string(prefix) + ".tmp-" +
      std::to_string(static_cast<unsigned long long>(::getpid())) + "-" +
      std::to_string(static_cast<unsigned long long>(current));
}

unique_fd
lock_attempt(int attempt_fd, short type)
{
  unique_fd lock(open_at(
      attempt_fd, "lock-v1", O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_CREAT,
      private_file_mode));
  if (lock.get() < 0)
    throw_error(rejected_store_error_code::attempt_locked, errno, {},
                "cannot open rejected-object attempt lock");
  struct stat status {};
  if (::fstat(lock.get(), &status) != 0 || !S_ISREG(status.st_mode))
    throw_error(rejected_store_error_code::attempt_locked, errno, {},
                "rejected-object attempt lock is not a regular file");
  struct flock record {};
  record.l_type = type;
  record.l_whence = SEEK_SET;
  record.l_start = 0;
  record.l_len = 0;
#ifdef F_OFD_SETLK
  constexpr int command = F_OFD_SETLK;
#else
  constexpr int command = F_SETLK;
#endif
  if (::fcntl(lock.get(), command, &record) != 0)
    throw_error(rejected_store_error_code::attempt_locked, errno, {},
                "cannot lock rejected-object attempt");
  return lock;
}

bool
same_file_bytes(int directory_fd,
                const std::string& name,
                const std::vector<std::byte>& expected)
{
  return read_file(
      directory_fd, name, rejected_store_error_code::record_read_failed,
      rejected_store_error_code::record_read_failed,
      std::max(maximum_record_size, expected.size())) == expected;
}

void
publish_immutable_bytes(int directory_fd,
                        const std::string& final_name,
                        const std::vector<std::byte>& bytes,
                        rejected_store_error_code write_code,
                        rejected_store_error_code sync_code,
                        rejected_store_error_code publish_code)
{
  const std::string temporary = temporary_name(final_name);
  unique_fd file(open_at(
      directory_fd, temporary.c_str(),
      O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL,
      private_file_mode));
  if (file.get() < 0)
    throw_error(write_code, errno, final_name,
                "cannot create rejected-object temporary file");
  bool keep = true;
  try {
    write_all(file.get(), bytes, write_code,
              "cannot write rejected-object temporary file");
    synchronize_fd(file.get(), sync_code,
                   "cannot synchronize rejected-object temporary file");
    if (::linkat(directory_fd, temporary.c_str(), directory_fd,
                 final_name.c_str(), 0) != 0)
    {
      if (errno != EEXIST || !same_file_bytes(directory_fd, final_name, bytes))
        throw_error(publish_code, errno, final_name,
                    "cannot publish immutable rejected-object file");
    }
    keep = false;
    static_cast<void>(::unlinkat(directory_fd, temporary.c_str(), 0));
  } catch (...) {
    if (keep)
      static_cast<void>(::unlinkat(directory_fd, temporary.c_str(), 0));
    throw;
  }
}

unique_fd
open_attempt_directory(
    int store_fd,
    const application_attempt& attempt,
    const pkgplan::operation_plan_identity* expected_plan,
    bool create)
{
  const std::string name = attempt_directory_name(attempt);
  if (create && ::mkdirat(store_fd, name.c_str(), private_directory_mode) != 0 &&
      errno != EEXIST)
  {
    throw_error(rejected_store_error_code::attempt_open_failed, errno, name,
                "cannot create rejected-object attempt directory");
  }
  unique_fd attempt_fd(open_at(
      store_fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (attempt_fd.get() < 0) {
    if (!create && errno == ENOENT)
      return unique_fd();
    throw_error(rejected_store_error_code::attempt_open_failed, errno, name,
                "cannot open rejected-object attempt directory");
  }
  require_directory(attempt_fd.get(), rejected_store_error_code::attempt_invalid,
                    "rejected-object attempt is not a directory");

  if (create && expected_plan == nullptr)
    throw std::logic_error(
        "rejected-object attempt creation requires plan authority");
  auto existing = read_file(
      attempt_fd.get(), "binding-v1",
      rejected_store_error_code::binding_read_failed,
      rejected_store_error_code::binding_read_failed,
      maximum_record_size, true);
  if (existing.empty()) {
    if (!create)
      return unique_fd();
    const auto expected = encode_binding(attempt, *expected_plan);
    publish_immutable_bytes(
        attempt_fd.get(), "binding-v1", expected,
        rejected_store_error_code::binding_write_failed,
        rejected_store_error_code::binding_write_failed,
        rejected_store_error_code::binding_write_failed);
  } else {
    const auto bound_plan = decode_binding(existing, attempt);
    if (expected_plan != nullptr && bound_plan != *expected_plan)
      throw_error(rejected_store_error_code::binding_mismatch, EINVAL, name,
                  "rejected-object attempt belongs to another plan");
    if (existing != encode_binding(attempt, bound_plan))
      throw_error(rejected_store_error_code::binding_mismatch, EINVAL, name,
                  "rejected-object binding is noncanonical");
  }
  return attempt_fd;
}

unique_fd
open_source_directory(int attempt_fd,
                      rejected_object_source source,
                      bool create)
{
  const char* name = source_directory_name(source);
  if (create && ::mkdirat(attempt_fd, name, private_directory_mode) != 0 &&
      errno != EEXIST)
  {
    throw_error(rejected_store_error_code::attempt_open_failed, errno, name,
                "cannot create rejected-object source directory");
  }
  unique_fd source_fd(open_at(
      attempt_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (source_fd.get() < 0) {
    if (!create && errno == ENOENT)
      return unique_fd();
    throw_error(rejected_store_error_code::attempt_open_failed, errno, name,
                "cannot open rejected-object source directory");
  }
  require_directory(source_fd.get(), rejected_store_error_code::attempt_invalid,
                    "rejected-object source is not a directory");
  return source_fd;
}

bool
same_observation(const application_path_observation& lhs,
                 const application_path_observation& rhs)
{
  return lhs.path() == rhs.path() && lhs.state() == rhs.state() &&
      lhs.object() == rhs.object();
}

completed_object_kind
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
  throw std::logic_error("invalid incoming package entry type");
}

application_path_observation
incoming_observation(const pkgimage::package_image& image,
                     const pkgimage::package_entry& entry)
{
  auto size = qualified_fact<std::uint64_t>::not_applicable();
  auto content =
      qualified_fact<completed_regular_content_identity>::not_applicable();
  auto symlink = qualified_fact<std::string>::not_applicable();
  auto device = qualified_fact<completed_device_number>::not_applicable();
  auto hardlink =
      qualified_fact<completed_hardlink_relation>::not_applicable();
  object_fact_completeness completeness = object_fact_completeness::complete;

  switch (entry.type) {
    case pkgimage::entry_type::regular:
      if (!entry.regular_content)
        throw_error(rejected_store_error_code::source_mismatch, EINVAL,
                    entry.path.string(),
                    "incoming regular entry lacks content authority");
      size = qualified_fact<std::uint64_t>::known(entry.size);
      content = qualified_fact<completed_regular_content_identity>::known(
          completed_regular_content_identity::parse(
              entry.regular_content->string()));
      hardlink = qualified_fact<completed_hardlink_relation>::unknown();
      completeness = object_fact_completeness::partial;
      break;

    case pkgimage::entry_type::hardlink: {
      if (!entry.hardlink_target)
        throw_error(rejected_store_error_code::source_mismatch, EINVAL,
                    entry.path.string(),
                    "incoming hard link lacks anchor authority");
      const auto* anchor = image.find(*entry.hardlink_target);
      if (anchor == nullptr || anchor->type != pkgimage::entry_type::regular ||
          !anchor->regular_content)
      {
        throw_error(rejected_store_error_code::source_mismatch, EINVAL,
                    entry.path.string(),
                    "incoming hard-link anchor lacks regular payload authority");
      }
      size = qualified_fact<std::uint64_t>::known(anchor->size);
      content = qualified_fact<completed_regular_content_identity>::known(
          completed_regular_content_identity::parse(
              anchor->regular_content->string()));
      hardlink = qualified_fact<completed_hardlink_relation>::known(
          completed_hardlink_relation(
              pkgplan::package_path::parse(entry.hardlink_target->string())));
      break;
    }

    case pkgimage::entry_type::symlink:
      if (!entry.symlink_target)
        throw_error(rejected_store_error_code::source_mismatch, EINVAL,
                    entry.path.string(),
                    "incoming symbolic link lacks target authority");
      symlink = qualified_fact<std::string>::known(*entry.symlink_target);
      break;

    case pkgimage::entry_type::character_device:
    case pkgimage::entry_type::block_device:
      if (!entry.device)
        throw_error(rejected_store_error_code::source_mismatch, EINVAL,
                    entry.path.string(),
                    "incoming device entry lacks device authority");
      device = qualified_fact<completed_device_number>::known(
          completed_device_number{entry.device->major, entry.device->minor});
      break;

    case pkgimage::entry_type::directory:
    case pkgimage::entry_type::fifo:
      break;
  }

  return application_path_observation::present(completed_object_fact(
      pkgplan::package_path::parse(entry.path.string()), incoming_kind(entry.type),
      qualified_fact<std::uint32_t>::known(entry.mode),
      qualified_fact<std::uint64_t>::known(entry.uid),
      qualified_fact<std::uint64_t>::known(entry.gid),
      std::move(size),
      qualified_fact<completed_object_timestamp>::known(
          completed_object_timestamp{entry.mtime, entry.mtime_nanoseconds}),
      std::move(content), std::move(symlink), std::move(device),
      std::move(hardlink), object_fact_provenance::incoming_image,
      completeness));
}

application_path_observation
rejected_capture_observation(const application_path_observation& captured)
{
  if (captured.state() != fact_state::known || !captured.object())
    throw_error(rejected_store_error_code::source_mismatch, EINVAL,
                captured.path().string(),
                "old rejected-object source is not a captured present object");
  const auto& object = *captured.object();
  return application_path_observation::present(completed_object_fact(
      pkgplan::package_path::parse(object.path().string()), object.kind(),
      object.mode(), object.uid(), object.gid(), object.size(), object.mtime(),
      object.regular_content(), object.symlink_target(), object.device(),
      object.hardlink(), object_fact_provenance::rejected_capture,
      object.completeness()));
}

struct regular_source final {
  unique_fd descriptor;
  std::uint64_t size;
  completed_regular_content_identity content;
};

regular_source
incoming_regular_source(const pkgimage::package_image& image,
                        const pkgimage::package_entry& entry,
                        const sealed_application_payloads& payloads)
{
  const pkgimage::package_entry* payload_entry = &entry;
  if (entry.type == pkgimage::entry_type::hardlink) {
    if (!entry.hardlink_target)
      throw_error(rejected_store_error_code::source_mismatch, EINVAL,
                  entry.path.string(), "hard link lacks anchor authority");
    payload_entry = image.find(*entry.hardlink_target);
  }
  if (payload_entry == nullptr ||
      payload_entry->type != pkgimage::entry_type::regular ||
      !payload_entry->regular_content)
  {
    throw_error(rejected_store_error_code::source_mismatch, EINVAL,
                entry.path.string(),
                "incoming rejected object lacks regular payload authority");
  }
  auto opened = payloads.open(payload_entry->id);
  unique_fd duplicate(duplicate_fd(
      opened.descriptor(), rejected_store_error_code::payload_open_failed,
      "cannot duplicate sealed incoming payload descriptor"));
  if (::lseek(duplicate.get(), 0, SEEK_SET) < 0)
    throw_error(rejected_store_error_code::payload_read_failed, errno,
                entry.path.string(), "cannot rewind sealed incoming payload");
  return regular_source{
      std::move(duplicate), opened.size(),
      completed_regular_content_identity::parse(
          payload_entry->regular_content->string())};
}

regular_source
old_regular_source(const captured_old_object& captured)
{
  auto opened = captured.open_regular();
  unique_fd duplicate(duplicate_fd(
      opened.descriptor(), rejected_store_error_code::payload_open_failed,
      "cannot duplicate captured old payload descriptor"));
  if (::lseek(duplicate.get(), 0, SEEK_SET) < 0)
    throw_error(rejected_store_error_code::payload_read_failed, errno,
                captured.request().path().string(),
                "cannot rewind captured old payload");
  const auto& object = *captured.observation().object();
  if (object.regular_content().state() != fact_state::known ||
      !object.regular_content().value())
  {
    throw_error(rejected_store_error_code::source_mismatch, EINVAL,
                captured.request().path().string(),
                "captured regular object lacks content identity");
  }
  return regular_source{
      std::move(duplicate), opened.size(), *object.regular_content().value()};
}

std::array<std::uint8_t, 32>
hash_and_copy(int source_fd,
              int destination_fd,
              std::uint64_t expected_size,
              const pkgplan::package_path& path)
{
  std::unique_ptr<EVP_MD_CTX, evp_context_deleter> context(EVP_MD_CTX_new());
  if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
    throw_error(rejected_store_error_code::payload_mismatch, EIO,
                path.string(), "cannot initialize rejected payload digest");

  std::array<std::byte, 64U * 1024U> buffer{};
  std::uint64_t total = 0;
  for (;;) {
    const ssize_t count = ::read(source_fd, buffer.data(), buffer.size());
    if (count < 0) {
      if (errno == EINTR)
        continue;
      throw_error(rejected_store_error_code::payload_read_failed, errno,
                  path.string(), "cannot read rejected payload source");
    }
    if (count == 0)
      break;
    const auto amount = static_cast<std::size_t>(count);
    if (total > expected_size || amount > expected_size - total)
      throw_error(rejected_store_error_code::payload_mismatch, EOVERFLOW,
                  path.string(), "rejected payload exceeds admitted size");
    if (EVP_DigestUpdate(context.get(), buffer.data(), amount) != 1)
      throw_error(rejected_store_error_code::payload_mismatch, EIO,
                  path.string(), "cannot update rejected payload digest");
    write_all(destination_fd, buffer.data(), amount,
              rejected_store_error_code::payload_write_failed,
              "cannot write rejected payload");
    total += amount;
  }
  if (total != expected_size)
    throw_error(rejected_store_error_code::payload_mismatch, EINVAL,
                path.string(), "rejected payload size changed");

  std::array<std::uint8_t, 32> digest{};
  unsigned int digest_size = 0;
  if (EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) != 1 ||
      digest_size != digest.size())
  {
    throw_error(rejected_store_error_code::payload_mismatch, EIO,
                path.string(), "cannot finalize rejected payload digest");
  }
  return digest;
}

bool
same_regular_payload(int directory_fd,
                     const std::string& name,
                     std::uint64_t size,
                     const completed_regular_content_identity& content,
                     const pkgplan::package_path& path)
{
  unique_fd file(open_at(
      directory_fd, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (file.get() < 0)
    throw_error(rejected_store_error_code::payload_open_failed, errno,
                path.string(), "cannot open existing rejected payload");
  struct stat status {};
  if (::fstat(file.get(), &status) != 0 || !S_ISREG(status.st_mode) ||
      status.st_size < 0 || static_cast<std::uint64_t>(status.st_size) != size)
  {
    return false;
  }
  std::unique_ptr<EVP_MD_CTX, evp_context_deleter> context(EVP_MD_CTX_new());
  if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
    throw_error(rejected_store_error_code::payload_mismatch, EIO,
                path.string(), "cannot initialize existing payload digest");
  std::array<std::byte, 64U * 1024U> buffer{};
  for (;;) {
    const ssize_t count = ::read(file.get(), buffer.data(), buffer.size());
    if (count < 0) {
      if (errno == EINTR)
        continue;
      throw_error(rejected_store_error_code::payload_read_failed, errno,
                  path.string(), "cannot read existing rejected payload");
    }
    if (count == 0)
      break;
    if (EVP_DigestUpdate(context.get(), buffer.data(),
                         static_cast<std::size_t>(count)) != 1)
    {
      throw_error(rejected_store_error_code::payload_mismatch, EIO,
                  path.string(), "cannot update existing payload digest");
    }
  }
  std::array<std::uint8_t, 32> digest{};
  unsigned int digest_size = 0;
  if (EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) != 1 ||
      digest_size != digest.size())
  {
    throw_error(rejected_store_error_code::payload_mismatch, EIO,
                path.string(), "cannot finalize existing payload digest");
  }
  return std::equal(digest.begin(), digest.end(), content.bytes().begin(),
                    content.bytes().end());
}

void
publish_regular_payload(int source_directory_fd,
                        const pkgplan::package_path& path,
                        regular_source source)
{
  const std::string final_name = payload_name(path);
  const std::string temporary = temporary_name(final_name);
  unique_fd file(open_at(
      source_directory_fd, temporary.c_str(),
      O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL,
      private_file_mode));
  if (file.get() < 0)
    throw_error(rejected_store_error_code::payload_write_failed, errno,
                path.string(), "cannot create rejected payload temporary file");
  bool keep = true;
  try {
    const auto digest = hash_and_copy(
        source.descriptor.get(), file.get(), source.size, path);
    if (!std::equal(digest.begin(), digest.end(), source.content.bytes().begin(),
                    source.content.bytes().end()))
    {
      throw_error(rejected_store_error_code::payload_mismatch, EINVAL,
                  path.string(), "rejected payload content identity changed");
    }
    synchronize_fd(file.get(), rejected_store_error_code::payload_sync_failed,
                   "cannot synchronize rejected payload temporary file");
    if (::linkat(source_directory_fd, temporary.c_str(), source_directory_fd,
                 final_name.c_str(), 0) != 0)
    {
      if (errno != EEXIST || !same_regular_payload(
              source_directory_fd, final_name, source.size, source.content, path))
      {
        throw_error(rejected_store_error_code::record_publish_failed, errno,
                    path.string(), "cannot publish immutable rejected payload");
      }
    }
    keep = false;
    static_cast<void>(::unlinkat(source_directory_fd, temporary.c_str(), 0));
  } catch (...) {
    if (keep)
      static_cast<void>(::unlinkat(source_directory_fd, temporary.c_str(), 0));
    throw;
  }
}

unique_fd
open_verified_payload(int source_directory_fd,
                      const rejected_record& record)
{
  if (!record.observation.object() ||
      record.observation.object()->kind() != completed_object_kind::regular)
  {
    throw_error(rejected_store_error_code::object_not_regular, EINVAL,
                record.request.path().string(),
                "rejected object is not regular");
  }
  const auto& object = *record.observation.object();
  if (object.size().state() != fact_state::known || !object.size().value() ||
      object.regular_content().state() != fact_state::known ||
      !object.regular_content().value())
  {
    throw_error(rejected_store_error_code::record_invalid, EINVAL,
                record.request.path().string(),
                "regular rejected record lacks payload facts");
  }
  const std::string name = payload_name(record.request.path());
  if (!same_regular_payload(source_directory_fd, name, *object.size().value(),
                            *object.regular_content().value(),
                            record.request.path()))
  {
    throw_error(rejected_store_error_code::payload_mismatch, EINVAL,
                record.request.path().string(),
                "rejected payload does not match its record");
  }
  unique_fd file(open_at(
      source_directory_fd, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (file.get() < 0)
    throw_error(rejected_store_error_code::payload_open_failed, errno,
                record.request.path().string(),
                "cannot reopen verified rejected payload");
  if (::lseek(file.get(), 0, SEEK_SET) < 0)
    throw_error(rejected_store_error_code::payload_read_failed, errno,
                record.request.path().string(),
                "cannot rewind verified rejected payload");
  return file;
}

rejected_object_source
source_for(const backend_rejected_effect_request& request)
{
  return request.source_side() ==
             pkgplan::rejected_object_source_side::incoming
      ? rejected_object_source::incoming
      : rejected_object_source::old;
}

bool
same_request(const backend_rejected_effect_request& lhs,
             const backend_rejected_effect_request& rhs)
{
  return lhs.path() == rhs.path() &&
      lhs.source_side() == rhs.source_side() &&
      lhs.reason() == rhs.reason() &&
      lhs.release() == rhs.release() &&
      lhs.artifact() == rhs.artifact() &&
      lhs.artifact_manifest() == rhs.artifact_manifest() &&
      lhs.image() == rhs.image() &&
      lhs.incoming_entry() == rhs.incoming_entry() &&
      lhs.installed_package() == rhs.installed_package() &&
      lhs.installed_control() == rhs.installed_control() &&
      lhs.observations() == rhs.observations();
}

rejected_object_publication_result
publish_record(int store_fd,
               const application_attempt& attempt,
               const pkgplan::operation_plan_identity& plan,
               const backend_rejected_effect_request& request,
               rejected_object_source source,
               application_path_observation observation,
               std::optional<regular_source> payload)
{
  unique_fd attempt_fd = open_attempt_directory(store_fd, attempt, &plan, true);
  unique_fd lock = lock_attempt(attempt_fd.get(), F_WRLCK);
  unique_fd source_fd = open_source_directory(attempt_fd.get(), source, true);
  const std::string name = record_name(request.path());
  auto existing = read_file(
      source_fd.get(), name, rejected_store_error_code::record_read_failed,
      rejected_store_error_code::record_read_failed,
      maximum_record_size, true);
  if (!existing.empty()) {
    rejected_record record = decode_record(existing, attempt, plan, request);
    if (!same_request(record.request, request) || record.source != source ||
        !same_observation(record.observation, observation))
    {
      throw_error(rejected_store_error_code::binding_mismatch, EINVAL,
                  request.path().string(),
                  "rejected-object record binding mismatch");
    }
    if (record.observation.object()->kind() == completed_object_kind::regular)
      static_cast<void>(open_verified_payload(source_fd.get(), record));
    return rejected_object_publication_result(
        backend_operation_outcome::completed, record.identity,
        {record_evidence(existing)});
  }

  if (observation.state() != fact_state::known || !observation.object())
    throw std::invalid_argument(
        "rejected-object publication requires one present object");
  const bool regular =
      observation.object()->kind() == completed_object_kind::regular;
  if (regular != payload.has_value())
    throw_error(rejected_store_error_code::source_mismatch, EINVAL,
                request.path().string(),
                "rejected-object payload applicability mismatch");
  if (payload)
    publish_regular_payload(source_fd.get(), request.path(), std::move(*payload));

  const auto body = encode_record_body(attempt, plan, request, source, observation);
  const auto identity = record_identity(body);
  const auto encoded = frame(
      record_magic, rejected_record_encoding_version, body);
  publish_immutable_bytes(
      source_fd.get(), name, encoded,
      rejected_store_error_code::record_write_failed,
      rejected_store_error_code::record_write_failed,
      rejected_store_error_code::record_publish_failed);
  return rejected_object_publication_result(
      backend_operation_outcome::completed, identity,
      {record_evidence(encoded)});
}

} // namespace

class published_rejected_object::implementation final {
public:
  implementation(unique_fd attempt_fd,
                 unique_fd source_fd,
                 rejected_record record)
      : attempt_fd_(std::move(attempt_fd)), source_fd_(std::move(source_fd)),
        record_(std::move(record))
  {
  }

  unique_fd attempt_fd_;
  unique_fd source_fd_;
  rejected_record record_;
};

rejected_store_error::rejected_store_error(
    rejected_store_error_code code,
    int system_error,
    std::string path,
    std::string message)
    : std::runtime_error(std::move(message)), code_(code),
      system_error_(system_error), path_(std::move(path))
{
}

rejected_store_error_code rejected_store_error::code() const noexcept
{ return code_; }
int rejected_store_error::system_error() const noexcept
{ return system_error_; }
const std::string& rejected_store_error::path() const noexcept
{ return path_; }

rejected_regular_object::rejected_regular_object(
    int descriptor, std::uint64_t size) noexcept
    : descriptor_(descriptor), size_(size)
{
}
rejected_regular_object::rejected_regular_object(
    rejected_regular_object&& other) noexcept
    : descriptor_(other.descriptor_), size_(other.size_)
{
  other.descriptor_ = -1;
  other.size_ = 0;
}
rejected_regular_object& rejected_regular_object::operator=(
    rejected_regular_object&& other) noexcept
{
  if (this != &other) {
    if (descriptor_ >= 0)
      static_cast<void>(::close(descriptor_));
    descriptor_ = other.descriptor_;
    size_ = other.size_;
    other.descriptor_ = -1;
    other.size_ = 0;
  }
  return *this;
}
rejected_regular_object::~rejected_regular_object()
{
  if (descriptor_ >= 0)
    static_cast<void>(::close(descriptor_));
}
int rejected_regular_object::descriptor() const noexcept
{ return descriptor_; }
std::uint64_t rejected_regular_object::size() const noexcept
{ return size_; }

published_rejected_object::published_rejected_object(
    std::unique_ptr<implementation> state)
    : state_(std::move(state))
{
}
published_rejected_object::published_rejected_object(
    published_rejected_object&&) noexcept = default;
published_rejected_object& published_rejected_object::operator=(
    published_rejected_object&&) noexcept = default;
published_rejected_object::~published_rejected_object() = default;
const application_attempt& published_rejected_object::attempt() const noexcept
{ return state_->record_.attempt; }
const pkgplan::operation_plan_identity&
published_rejected_object::plan() const noexcept
{ return state_->record_.plan; }
const backend_rejected_effect_request&
published_rejected_object::request() const noexcept
{ return state_->record_.request; }
rejected_object_source published_rejected_object::source() const noexcept
{ return state_->record_.source; }
const application_path_observation&
published_rejected_object::observation() const noexcept
{ return state_->record_.observation; }
const rejected_object_record_identity&
published_rejected_object::identity() const noexcept
{ return state_->record_.identity; }
rejected_regular_object published_rejected_object::open_regular() const
{
  unique_fd file = open_verified_payload(state_->source_fd_.get(), state_->record_);
  const auto size = *state_->record_.observation.object()->size().value();
  return rejected_regular_object(file.release(), size);
}

application_rejected_object_store::application_rejected_object_store(
    int directory_fd) noexcept
    : directory_fd_(directory_fd)
{
}

application_rejected_object_store application_rejected_object_store::open(
    const std::string& directory)
{
  unique_fd store(open_path(
      directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (store.get() < 0)
    throw rejected_store_error(
        rejected_store_error_code::directory_open_failed, errno, directory,
        "cannot open rejected-object directory");
  require_directory(store.get(), rejected_store_error_code::directory_invalid,
                    "rejected-object descriptor is not a directory");
  return application_rejected_object_store(store.release());
}

application_rejected_object_store
application_rejected_object_store::from_directory_fd(int directory_fd)
{
  require_directory(directory_fd, rejected_store_error_code::directory_invalid,
                    "rejected-object descriptor is not a directory");
  unique_fd duplicate(duplicate_fd(
      directory_fd, rejected_store_error_code::directory_invalid,
      "cannot duplicate rejected-object descriptor"));
  return application_rejected_object_store(duplicate.release());
}

application_rejected_object_store::application_rejected_object_store(
    application_rejected_object_store&& other) noexcept
    : directory_fd_(other.directory_fd_)
{
  other.directory_fd_ = -1;
}

application_rejected_object_store&
application_rejected_object_store::operator=(
    application_rejected_object_store&& other) noexcept
{
  if (this != &other) {
    if (directory_fd_ >= 0)
      static_cast<void>(::close(directory_fd_));
    directory_fd_ = other.directory_fd_;
    other.directory_fd_ = -1;
  }
  return *this;
}

application_rejected_object_store::~application_rejected_object_store()
{
  if (directory_fd_ >= 0)
    static_cast<void>(::close(directory_fd_));
}

namespace {

rejected_object_publication_result
publish_incoming_record(
    int directory_fd,
    const application_attempt& attempt,
    const pkgplan::operation_plan_identity& plan,
    const backend_rejected_effect_request& request,
    const pkgimage::package_image& image,
    const sealed_application_payloads* payloads)
{
  if (directory_fd < 0)
    throw rejected_store_error(
        rejected_store_error_code::directory_invalid, EBADF, {},
        "rejected-object store is not open");
  if (source_for(request) != rejected_object_source::incoming ||
      !request.incoming_entry())
  {
    throw std::invalid_argument(
        "incoming rejected publication requires stage_incoming authority");
  }
  if (payloads != nullptr &&
      (payloads->attempt().identity() != attempt.identity() ||
       payloads->attempt_nonce() != attempt.nonce() ||
       payloads->image() != image.identity()))
  {
    throw_error(rejected_store_error_code::source_mismatch, EINVAL,
                request.path().string(),
                "sealed incoming payload authority does not match attempt");
  }
  const auto* entry = image.entry(*request.incoming_entry());
  if (entry == nullptr || entry->path.string() != request.path().string())
    throw_error(rejected_store_error_code::source_mismatch, EINVAL,
                request.path().string(),
                "incoming rejected request does not match image entry");

  auto observation = incoming_observation(image, *entry);
  std::optional<regular_source> payload;
  if (observation.object()->kind() == completed_object_kind::regular) {
    if (payloads == nullptr)
      throw_error(rejected_store_error_code::source_unavailable, ENOENT,
                  request.path().string(),
                  "incoming regular rejected object lacks sealed payload authority");
    payload.emplace(incoming_regular_source(image, *entry, *payloads));
  }
  return publish_record(directory_fd, attempt, plan, request,
                        rejected_object_source::incoming,
                        std::move(observation), std::move(payload));
}

} // namespace

rejected_object_publication_result
application_rejected_object_store::publish_incoming(
    const application_attempt& attempt,
    const pkgplan::operation_plan_identity& plan,
    const backend_rejected_effect_request& request,
    const pkgimage::package_image& image) const
{
  return publish_incoming_record(
      directory_fd_, attempt, plan, request, image, nullptr);
}

rejected_object_publication_result
application_rejected_object_store::publish_incoming(
    const application_attempt& attempt,
    const pkgplan::operation_plan_identity& plan,
    const backend_rejected_effect_request& request,
    const pkgimage::package_image& image,
    const sealed_application_payloads& payloads) const
{
  return publish_incoming_record(
      directory_fd_, attempt, plan, request, image, &payloads);
}

rejected_object_publication_result
application_rejected_object_store::publish_old(
    const application_attempt& attempt,
    const pkgplan::operation_plan_identity& plan,
    const backend_rejected_effect_request& request,
    const captured_old_object& captured) const
{
  if (directory_fd_ < 0)
    throw rejected_store_error(
        rejected_store_error_code::directory_invalid, EBADF, {},
        "rejected-object store is not open");
  if (source_for(request) != rejected_object_source::old ||
      request.incoming_entry())
  {
    throw std::invalid_argument(
        "old rejected publication requires stage_old authority");
  }
  if (captured.attempt().identity() != attempt.identity() ||
      captured.request().path() != request.path() ||
      !captured.request().for_rejected_object())
  {
    throw_error(rejected_store_error_code::source_mismatch, EINVAL,
                request.path().string(),
                "captured old authority does not match rejected request");
  }

  auto observation = rejected_capture_observation(captured.observation());
  std::optional<regular_source> payload;
  if (observation.object()->kind() == completed_object_kind::regular)
    payload.emplace(old_regular_source(captured));
  return publish_record(directory_fd_, attempt, plan, request,
                        rejected_object_source::old,
                        std::move(observation), std::move(payload));
}

std::optional<published_rejected_object>
application_rejected_object_store::load(
    const application_attempt& attempt,
    const pkgplan::operation_plan_identity& plan,
    const backend_rejected_effect_request& request) const
{
  if (directory_fd_ < 0)
    throw rejected_store_error(
        rejected_store_error_code::directory_invalid, EBADF, {},
        "rejected-object store is not open");
  const auto source = source_for(request);
  unique_fd attempt_fd = open_attempt_directory(
      directory_fd_, attempt, &plan, false);
  if (attempt_fd.get() < 0)
    return std::nullopt;
  unique_fd lock = lock_attempt(attempt_fd.get(), F_RDLCK);
  unique_fd source_fd = open_source_directory(attempt_fd.get(), source, false);
  if (source_fd.get() < 0)
    return std::nullopt;
  const std::string name = record_name(request.path());
  auto bytes = read_file(
      source_fd.get(), name, rejected_store_error_code::record_read_failed,
      rejected_store_error_code::record_read_failed,
      maximum_record_size, true);
  if (bytes.empty())
    return std::nullopt;
  rejected_record record = decode_record(bytes, attempt, plan, request);
  if (!same_request(record.request, request) || record.source != source)
    throw rejected_store_error(
        rejected_store_error_code::binding_mismatch, EINVAL,
        request.path().string(), "rejected-object record binding mismatch");
  if (record.observation.object()->kind() == completed_object_kind::regular)
    static_cast<void>(open_verified_payload(source_fd.get(), record));
  return published_rejected_object(
      std::make_unique<published_rejected_object::implementation>(
          std::move(attempt_fd), std::move(source_fd), std::move(record)));
}

void application_rejected_object_store::synchronize(
    const application_attempt& attempt) const
{
  if (directory_fd_ < 0)
    throw rejected_store_error(
        rejected_store_error_code::directory_invalid, EBADF, {},
        "rejected-object store is not open");
  unique_fd attempt_fd = open_attempt_directory(
      directory_fd_, attempt, nullptr, false);
  if (attempt_fd.get() < 0)
    throw rejected_store_error(
        rejected_store_error_code::attempt_open_failed, ENOENT, {},
        "rejected-object attempt is not published");
  unique_fd lock = lock_attempt(attempt_fd.get(), F_RDLCK);
  for (const auto source : {rejected_object_source::incoming,
                            rejected_object_source::old}) {
    unique_fd source_fd = open_source_directory(attempt_fd.get(), source, false);
    if (source_fd.get() >= 0)
      synchronize_fd(source_fd.get(),
                     rejected_store_error_code::namespace_sync_failed,
                     "cannot synchronize rejected-object source directory");
  }
  synchronize_fd(attempt_fd.get(),
                 rejected_store_error_code::namespace_sync_failed,
                 "cannot synchronize rejected-object attempt directory");
  synchronize_fd(directory_fd_,
                 rejected_store_error_code::namespace_sync_failed,
                 "cannot synchronize rejected-object store directory");
}

} // namespace pkgapply::posix
