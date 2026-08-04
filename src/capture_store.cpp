// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/capture_store.h>

#include <algorithm>
#include <atomic>
#include <array>
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
#include <sys/sysmacros.h>
#include <unistd.h>

namespace pkgapply::posix {
namespace {

constexpr std::array<std::byte, 8> binding_magic{
    std::byte{'Z'}, std::byte{'P'}, std::byte{'L'}, std::byte{'C'},
    std::byte{'A'}, std::byte{'B'}, std::byte{'N'}, std::byte{'D'}};
constexpr std::array<std::byte, 8> record_magic{
    std::byte{'Z'}, std::byte{'P'}, std::byte{'L'}, std::byte{'C'},
    std::byte{'A'}, std::byte{'P'}, std::byte{'O'}, std::byte{'B'}};
constexpr std::uint16_t capture_encoding_version = 1;
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

struct resolved_leaf final {
  unique_fd parent;
  std::string leaf;
  bool parent_missing;
};

struct captured_record final {
  application_attempt attempt;
  old_object_capture_request request;
  application_path_observation observation;
  bool exact_recovery_possible;
};

[[noreturn]] void
throw_error(capture_store_error_code code,
            int system_error,
            std::string path,
            std::string message)
{
  throw capture_store_error(
      code, system_error, std::move(path), std::move(message));
}

void
set_close_on_exec(int fd, capture_store_error_code code)
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
duplicate_fd(int fd, capture_store_error_code code, const char* message)
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
                  capture_store_error_code code,
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
               capture_store_error_code code,
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
          capture_store_error_code code,
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
          capture_store_error_code code,
          const char* message)
{
  write_all(fd, bytes.data(), bytes.size(), code, message);
}

std::vector<std::byte>
read_file(int directory_fd,
          const std::string& name,
          capture_store_error_code open_code,
          capture_store_error_code read_code,
          std::size_t maximum,
          bool absent_is_empty = false)
{
  unique_fd file(open_at(
      directory_fd, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (file.get() < 0) {
    if (absent_is_empty && errno == ENOENT)
      return {};
    throw_error(open_code, errno, name, "cannot open private capture record");
  }

  struct stat status {};
  if (::fstat(file.get(), &status) != 0)
    throw_error(read_code, errno, name, "cannot inspect private capture record");
  if (!S_ISREG(status.st_mode) || status.st_size < 0 ||
      static_cast<std::uint64_t>(status.st_size) > maximum)
  {
    throw_error(read_code, EINVAL, name,
                "private capture record has invalid type or size");
  }

  std::vector<std::byte> bytes(static_cast<std::size_t>(status.st_size));
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count = ::read(
        file.get(), bytes.data() + offset, bytes.size() - offset);
    if (count < 0) {
      if (errno == EINTR)
        continue;
      throw_error(read_code, errno, name, "cannot read private capture record");
    }
    if (count == 0)
      throw_error(read_code, EIO, name,
                  "private capture record was truncated while reading");
    offset += static_cast<std::size_t>(count);
  }
  std::byte probe{};
  for (;;) {
    const ssize_t count = ::read(file.get(), &probe, 1);
    if (count < 0 && errno == EINTR)
      continue;
    if (count < 0)
      throw_error(read_code, errno, name,
                  "cannot finish reading private capture record");
    if (count != 0)
      throw_error(read_code, EIO, name,
                  "private capture record changed size while reading");
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
    throw_error(capture_store_error_code::record_invalid, EIO, {},
                "cannot calculate private capture digest");
  }
  std::array<std::uint8_t, 32> digest{};
  unsigned int digest_size = 0;
  if (EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) != 1 ||
      digest_size != digest.size())
  {
    throw_error(capture_store_error_code::record_invalid, EIO, {},
                "cannot finalize private capture digest");
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

void
append_u8(std::vector<std::byte>& bytes, std::uint8_t value)
{
  bytes.push_back(static_cast<std::byte>(value));
}

void
append_u16(std::vector<std::byte>& bytes, std::uint16_t value)
{
  append_u8(bytes, static_cast<std::uint8_t>((value >> 8U) & 0xffU));
  append_u8(bytes, static_cast<std::uint8_t>(value & 0xffU));
}

void
append_u32(std::vector<std::byte>& bytes, std::uint32_t value)
{
  for (int shift = 24; shift >= 0; shift -= 8)
    append_u8(bytes, static_cast<std::uint8_t>((value >> shift) & 0xffU));
}

void
append_u64(std::vector<std::byte>& bytes, std::uint64_t value)
{
  for (int shift = 56; shift >= 0; shift -= 8)
    append_u8(bytes, static_cast<std::uint8_t>((value >> shift) & 0xffU));
}

void
append_i64(std::vector<std::byte>& bytes, std::int64_t value)
{
  const bool negative = value < 0;
  const std::uint64_t magnitude = negative
      ? static_cast<std::uint64_t>(-(value + 1)) + 1U
      : static_cast<std::uint64_t>(value);
  append_u8(bytes, negative ? 1U : 0U);
  append_u64(bytes, magnitude);
}

void
append_string(std::vector<std::byte>& bytes, const std::string& value)
{
  if (value.size() > std::numeric_limits<std::uint32_t>::max())
    throw_error(capture_store_error_code::record_invalid, EOVERFLOW, {},
                "private capture string is too large");
  append_u32(bytes, static_cast<std::uint32_t>(value.size()));
  bytes.insert(bytes.end(),
               reinterpret_cast<const std::byte*>(value.data()),
               reinterpret_cast<const std::byte*>(value.data() + value.size()));
}

class byte_reader final {
public:
  explicit byte_reader(const std::vector<std::byte>& bytes)
      : bytes_(bytes) {}

  [[nodiscard]] std::uint8_t u8()
  {
    require(1);
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
      invalid("private capture record contains trailing data");
  }
private:
  [[noreturn]] static void invalid(const char* message)
  {
    throw_error(capture_store_error_code::record_invalid, EINVAL, {}, message);
  }
  void require(std::size_t size)
  {
    if (size > bytes_.size() - offset_)
      invalid("private capture record is truncated");
  }
  const std::vector<std::byte>& bytes_;
  std::size_t offset_ = 0;
};

std::vector<std::byte>
frame(const std::array<std::byte, 8>& magic,
      const std::vector<std::byte>& body)
{
  const auto checksum = sha256_bytes(body.data(), body.size());
  std::vector<std::byte> bytes;
  bytes.reserve(magic.size() + 2U + 8U + checksum.size() + body.size());
  bytes.insert(bytes.end(), magic.begin(), magic.end());
  append_u16(bytes, capture_encoding_version);
  append_u64(bytes, body.size());
  for (const std::uint8_t byte : checksum)
    append_u8(bytes, byte);
  bytes.insert(bytes.end(), body.begin(), body.end());
  return bytes;
}

std::vector<std::byte>
unframe(const std::vector<std::byte>& bytes,
        const std::array<std::byte, 8>& magic)
{
  constexpr std::size_t envelope = 8U + 2U + 8U + 32U;
  if (bytes.size() < envelope)
    throw_error(capture_store_error_code::record_invalid, EINVAL, {},
                "private capture record is truncated");
  byte_reader reader(bytes);
  const auto observed_magic = reader.bytes(magic.size());
  if (!std::equal(observed_magic.begin(), observed_magic.end(), magic.begin()))
    throw_error(capture_store_error_code::record_invalid, EINVAL, {},
                "private capture record has invalid magic");
  if (reader.u16() != capture_encoding_version)
    throw_error(capture_store_error_code::record_invalid, EINVAL, {},
                "private capture record has unsupported version");
  const std::uint64_t body_size = reader.u64();
  if (body_size > maximum_record_size || body_size > bytes.size() - envelope)
    throw_error(capture_store_error_code::record_invalid, EINVAL, {},
                "private capture record is truncated or oversized");
  if (body_size != bytes.size() - envelope)
    throw_error(capture_store_error_code::record_invalid, EINVAL, {},
                "private capture record contains trailing data");
  const auto expected_checksum = reader.bytes(32U);
  const auto body = reader.bytes(static_cast<std::size_t>(body_size));
  reader.finish();
  const auto checksum = sha256_bytes(body.data(), body.size());
  if (!std::equal(expected_checksum.begin(), expected_checksum.end(),
                  reinterpret_cast<const std::byte*>(checksum.data())))
  {
    throw_error(capture_store_error_code::record_invalid, EINVAL, {},
                "private capture record checksum mismatch");
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
    throw_error(capture_store_error_code::binding_mismatch, EINVAL, {},
                "private capture attempt binding mismatch");
  }
  application_attempt_nonce::byte_array nonce{};
  for (auto& byte : nonce)
    byte = reader.u8();
  if (application_attempt_nonce::from_bytes(nonce) != attempt.nonce())
    throw_error(capture_store_error_code::binding_mismatch, EINVAL, {},
                "private capture attempt nonce mismatch");
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
    throw_error(capture_store_error_code::record_invalid, EINVAL, {},
                "private capture record has invalid fact state");
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
  throw_error(capture_store_error_code::record_invalid, EINVAL, {},
              "private capture record has invalid fact state");
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
    throw_error(capture_store_error_code::record_invalid, EINVAL, {},
                "private capture record has invalid observation state");

  const auto kind_value = reader.u8();
  if (kind_value < static_cast<std::uint8_t>(completed_object_kind::regular) ||
      kind_value > static_cast<std::uint8_t>(completed_object_kind::other))
  {
    throw_error(capture_store_error_code::record_invalid, EINVAL, {},
                "private capture record has invalid object kind");
  }
  const auto provenance_value = reader.u8();
  if (provenance_value <
          static_cast<std::uint8_t>(object_fact_provenance::incoming_image) ||
      provenance_value >
          static_cast<std::uint8_t>(object_fact_provenance::rejected_capture))
  {
    throw_error(capture_store_error_code::record_invalid, EINVAL, {},
                "private capture record has invalid provenance");
  }
  const auto completeness_value = reader.u8();
  if (completeness_value <
          static_cast<std::uint8_t>(object_fact_completeness::complete) ||
      completeness_value >
          static_cast<std::uint8_t>(object_fact_completeness::partial))
  {
    throw_error(capture_store_error_code::record_invalid, EINVAL, {},
                "private capture record has invalid completeness");
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
encode_binding(const application_attempt& attempt)
{
  return frame(binding_magic, encode_attempt_body(attempt));
}

void
validate_binding(const std::vector<std::byte>& bytes,
                 const application_attempt& attempt)
{
  const auto body = unframe(bytes, binding_magic);
  byte_reader reader(body);
  require_attempt_body(reader, attempt);
  reader.finish();
}

std::vector<std::byte>
encode_record(const captured_record& record)
{
  std::vector<std::byte> body = encode_attempt_body(record.attempt);
  append_string(body, record.request.path().string());
  append_u8(body, record.request.for_rejected_object() ? 1U : 0U);
  append_u8(body, record.request.for_recovery() ? 1U : 0U);
  append_u8(body, record.exact_recovery_possible ? 1U : 0U);
  append_observation(body, record.observation);
  return frame(record_magic, body);
}

captured_record
decode_record(const std::vector<std::byte>& bytes,
              const application_attempt& attempt)
{
  const auto body = unframe(bytes, record_magic);
  byte_reader reader(body);
  require_attempt_body(reader, attempt);
  auto path = pkgplan::package_path::parse(reader.string());
  const auto rejected = reader.u8();
  const auto recovery = reader.u8();
  const auto exact = reader.u8();
  if (rejected > 1U || recovery > 1U || exact > 1U ||
      (rejected == 0U && recovery == 0U))
  {
    throw_error(capture_store_error_code::record_invalid, EINVAL, {},
                "private capture record has invalid flags");
  }
  auto observation = read_observation(reader);
  reader.finish();
  if (observation.path() != path || observation.state() != fact_state::known)
    throw_error(capture_store_error_code::record_invalid, EINVAL, {},
                "private capture record has invalid observation binding");
  return captured_record{
      attempt,
      old_object_capture_request(std::move(path), rejected != 0U, recovery != 0U),
      std::move(observation), exact != 0U};
}

std::string
attempt_directory_name(const application_attempt& attempt)
{
  return "capture-v1-" + hexadecimal(
      attempt.identity().bytes().data(), attempt.identity().bytes().size());
}

std::string
path_key(const pkgplan::package_path& path)
{
  const auto digest = sha256_text(path.string());
  return hexadecimal(digest.data(), digest.size());
}

std::string
record_name(const pkgplan::package_path& path)
{
  return "record-v1-" + path_key(path);
}

std::string
payload_name(const pkgplan::package_path& path)
{
  return "payload-v1-" + path_key(path);
}

std::string
temporary_name(std::string_view prefix)
{
  static std::atomic<std::uint64_t> sequence{0};
  const std::uint64_t current = sequence.fetch_add(1U, std::memory_order_relaxed) + 1U;
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
    throw_error(capture_store_error_code::attempt_locked, errno, {},
                "cannot open private capture lock");
  struct stat status {};
  if (::fstat(lock.get(), &status) != 0 || !S_ISREG(status.st_mode))
    throw_error(capture_store_error_code::attempt_locked, errno, {},
                "private capture lock is not a regular file");
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
    throw_error(capture_store_error_code::attempt_locked, errno, {},
                "cannot lock private capture attempt");
  return lock;
}

bool
same_file_bytes(int directory_fd,
                const std::string& name,
                const std::vector<std::byte>& expected)
{
  const auto actual = read_file(
      directory_fd, name, capture_store_error_code::record_read_failed,
      capture_store_error_code::record_read_failed,
      std::max(maximum_record_size, expected.size()));
  return actual == expected;
}

void
publish_immutable_bytes(int directory_fd,
                        const std::string& final_name,
                        const std::vector<std::byte>& bytes,
                        capture_store_error_code write_code,
                        capture_store_error_code sync_code,
                        capture_store_error_code publish_code)
{
  const std::string temporary = temporary_name(final_name);
  unique_fd file(open_at(
      directory_fd, temporary.c_str(),
      O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL,
      private_file_mode));
  if (file.get() < 0)
    throw_error(write_code, errno, final_name,
                "cannot create private capture temporary file");
  bool keep = true;
  try {
    write_all(file.get(), bytes, write_code,
              "cannot write private capture temporary file");
    synchronize_fd(file.get(), sync_code,
                   "cannot synchronize private capture temporary file");
    if (::linkat(directory_fd, temporary.c_str(), directory_fd,
                 final_name.c_str(), 0) != 0)
    {
      if (errno != EEXIST || !same_file_bytes(directory_fd, final_name, bytes))
        throw_error(publish_code, errno, final_name,
                    "cannot publish immutable private capture file");
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
open_attempt_directory(int store_fd,
                       const application_attempt& attempt,
                       bool create)
{
  const std::string name = attempt_directory_name(attempt);
  if (create && ::mkdirat(store_fd, name.c_str(), private_directory_mode) != 0 &&
      errno != EEXIST)
  {
    throw_error(capture_store_error_code::attempt_open_failed, errno, name,
                "cannot create private capture attempt directory");
  }
  unique_fd attempt_fd(open_at(
      store_fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (attempt_fd.get() < 0) {
    if (!create && errno == ENOENT)
      return unique_fd();
    throw_error(capture_store_error_code::attempt_open_failed, errno, name,
                "cannot open private capture attempt directory");
  }
  require_directory(attempt_fd.get(), capture_store_error_code::attempt_invalid,
                    "private capture attempt is not a directory");

  const auto expected = encode_binding(attempt);
  auto existing = read_file(
      attempt_fd.get(), "binding-v1",
      capture_store_error_code::binding_read_failed,
      capture_store_error_code::binding_read_failed,
      maximum_record_size, true);
  if (existing.empty()) {
    if (!create)
      return unique_fd();
    publish_immutable_bytes(
        attempt_fd.get(), "binding-v1", expected,
        capture_store_error_code::binding_write_failed,
        capture_store_error_code::binding_write_failed,
        capture_store_error_code::binding_write_failed);
  } else {
    validate_binding(existing, attempt);
    if (existing != expected)
      throw_error(capture_store_error_code::binding_mismatch, EINVAL, name,
                  "private capture binding is noncanonical");
  }
  return attempt_fd;
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
    begin = end + 1U;
  }
  return result;
}

resolved_leaf
resolve_parent(int root_fd, const pkgplan::package_path& path)
{
  const auto parts = components(path);
  unique_fd current(duplicate_fd(
      root_fd, capture_store_error_code::target_root_invalid,
      "cannot duplicate target root descriptor"));
  for (std::size_t index = 0; index + 1U < parts.size(); ++index) {
    const std::string component(parts[index]);
    const int next = open_at(
        current.get(), component.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (next >= 0) {
      current.reset(next);
      continue;
    }
    const int failure = errno;
    if (failure == ENOENT || failure == ENOTDIR)
      return resolved_leaf{std::move(current), std::string(parts.back()), true};
    struct stat status {};
    if (::fstatat(current.get(), component.c_str(), &status,
                  AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(status.st_mode))
    {
      throw_error(capture_store_error_code::path_resolution_failed, ELOOP,
                  path.string(),
                  "capture path contains a symbolic-link parent");
    }
    throw_error(capture_store_error_code::path_resolution_failed, failure,
                path.string(), "cannot resolve capture path parent");
  }
  return resolved_leaf{std::move(current), std::string(parts.back()), false};
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

bool
same_observation(const application_path_observation& lhs,
                 const application_path_observation& rhs) noexcept
{
  return lhs.path() == rhs.path() && lhs.state() == rhs.state() &&
      lhs.object() == rhs.object();
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

template<class Value>
bool
known_matches(const qualified_fact<Value>& fact, const Value& value)
{
  return fact.state() != fact_state::known || *fact.value() == value;
}

template<class Value>
bool
known(const qualified_fact<Value>& fact) noexcept
{
  return fact.state() == fact_state::known;
}

bool
metadata_matches(const completed_object_fact& object,
                 const struct stat& status)
{
  return object.kind() == object_kind(status.st_mode) &&
      known_matches(object.mode(),
                    static_cast<std::uint32_t>(status.st_mode & 07777)) &&
      known_matches(object.uid(), static_cast<std::uint64_t>(status.st_uid)) &&
      known_matches(object.gid(), static_cast<std::uint64_t>(status.st_gid)) &&
      known_matches(object.mtime(), completed_object_timestamp{
          status.st_mtim.tv_sec,
          static_cast<std::uint32_t>(status.st_mtim.tv_nsec)});
}

bool
base_exact_metadata(const completed_object_fact& object) noexcept
{
  return known(object.mode()) && known(object.uid()) && known(object.gid()) &&
      known(object.mtime());
}

std::optional<struct stat>
stat_target_leaf(int root_fd, const pkgplan::package_path& path)
{
  resolved_leaf leaf = resolve_parent(root_fd, path);
  if (leaf.parent_missing)
    return std::nullopt;
  struct stat status {};
  if (::fstatat(leaf.parent.get(), leaf.leaf.c_str(), &status,
                AT_SYMLINK_NOFOLLOW) != 0)
  {
    if (errno == ENOENT)
      return std::nullopt;
    throw_error(capture_store_error_code::source_stat_failed, errno,
                path.string(), "cannot stat hard-link anchor");
  }
  return status;
}

bool
verify_hardlink(int root_fd,
                const completed_object_fact& object,
                const struct stat& status)
{
  if (object.hardlink().state() != fact_state::known ||
      object.hardlink().value()->anchor() == object.path())
    return false;
  const auto anchor = stat_target_leaf(
      root_fd, object.hardlink().value()->anchor());
  return anchor && S_ISREG(anchor->st_mode) &&
      anchor->st_dev == status.st_dev && anchor->st_ino == status.st_ino;
}

class temporary_capture_file final {
public:
  temporary_capture_file(int directory_fd, std::string name, unique_fd file)
      : directory_fd_(directory_fd), name_(std::move(name)), file_(std::move(file)) {}
  temporary_capture_file(const temporary_capture_file&) = delete;
  temporary_capture_file& operator=(const temporary_capture_file&) = delete;
  temporary_capture_file(temporary_capture_file&& other) noexcept
      : directory_fd_(other.directory_fd_), name_(std::move(other.name_)),
        file_(std::move(other.file_)), active_(other.active_)
  {
    other.active_ = false;
  }
  temporary_capture_file& operator=(temporary_capture_file&& other) noexcept
  {
    if (this != &other) {
      remove();
      directory_fd_ = other.directory_fd_;
      name_ = std::move(other.name_);
      file_ = std::move(other.file_);
      active_ = other.active_;
      other.active_ = false;
    }
    return *this;
  }
  ~temporary_capture_file() { remove(); }
  [[nodiscard]] int descriptor() const noexcept { return file_.get(); }
  [[nodiscard]] const std::string& name() const noexcept { return name_; }
  void remove() noexcept
  {
    if (active_) {
      static_cast<void>(::unlinkat(directory_fd_, name_.c_str(), 0));
      active_ = false;
    }
  }
private:
  int directory_fd_ = -1;
  std::string name_;
  unique_fd file_;
  bool active_ = true;
};

struct source_capture final {
  backend_operation_outcome outcome;
  bool exact_recovery_possible;
  std::optional<temporary_capture_file> regular_payload;
};

source_capture
capture_source(int root_fd,
               int attempt_fd,
               const application_path_observation& admitted)
{
  const auto& path = admitted.path();
  if (admitted.state() != fact_state::known || !admitted.object())
    throw std::invalid_argument("old-object capture requires a present observation");
  const auto& object = *admitted.object();

  resolved_leaf leaf = resolve_parent(root_fd, path);
  if (leaf.parent_missing)
    return {backend_operation_outcome::failed, false, std::nullopt};

  struct stat before {};
  if (::fstatat(leaf.parent.get(), leaf.leaf.c_str(), &before,
                AT_SYMLINK_NOFOLLOW) != 0)
  {
    if (errno == ENOENT)
      return {backend_operation_outcome::failed, false, std::nullopt};
    throw_error(capture_store_error_code::source_stat_failed, errno,
                path.string(), "cannot stat old target object");
  }
  if (!metadata_matches(object, before))
    return {backend_operation_outcome::failed, false, std::nullopt};

  const completed_object_kind kind = object_kind(before.st_mode);
  if (kind == completed_object_kind::socket ||
      kind == completed_object_kind::other)
  {
    return {backend_operation_outcome::failed, false, std::nullopt};
  }

  bool exact = base_exact_metadata(object);
  std::optional<temporary_capture_file> regular_payload;

  if (kind == completed_object_kind::regular) {
    unique_fd source(open_at(
        leaf.parent.get(), leaf.leaf.c_str(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (source.get() < 0) {
      if (errno == ENOENT)
        return {backend_operation_outcome::failed, false, std::nullopt};
      throw_error(capture_store_error_code::source_open_failed, errno,
                  path.string(), "cannot open old regular object");
    }
    struct stat opened {};
    if (::fstat(source.get(), &opened) != 0)
      throw_error(capture_store_error_code::source_stat_failed, errno,
                  path.string(), "cannot stat opened old regular object");
    if (!S_ISREG(opened.st_mode) || !same_object(before, opened))
      return {backend_operation_outcome::indeterminate, false, std::nullopt};
    if (opened.st_size < 0) {
      throw_error(capture_store_error_code::source_read_failed, EOVERFLOW,
                  path.string(), "old regular object is too large");
    }
    const std::string temporary = temporary_name("captured-payload");
    unique_fd payload_fd(open_at(
        attempt_fd, temporary.c_str(),
        O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL,
        private_file_mode));
    if (payload_fd.get() < 0)
      throw_error(capture_store_error_code::payload_open_failed, errno,
                  path.string(), "cannot create captured regular payload");
    temporary_capture_file payload(
        attempt_fd, temporary, std::move(payload_fd));

    std::unique_ptr<EVP_MD_CTX, evp_context_deleter> context(EVP_MD_CTX_new());
    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
      throw_error(capture_store_error_code::payload_write_failed, EIO,
                  path.string(), "cannot initialize captured payload digest");
    std::uint64_t copied_size = 0;
    std::array<std::byte, 64U * 1024U> buffer{};
    for (;;) {
      const ssize_t count = ::read(source.get(), buffer.data(), buffer.size());
      if (count > 0) {
        const auto amount = static_cast<std::size_t>(count);
        write_all(payload.descriptor(), buffer.data(), amount,
                  capture_store_error_code::payload_write_failed,
                  "cannot write captured regular payload");
        if (EVP_DigestUpdate(context.get(), buffer.data(), amount) != 1)
          throw_error(capture_store_error_code::payload_write_failed, EIO,
                      path.string(), "cannot update captured payload digest");
        if (amount > std::numeric_limits<std::uint64_t>::max() - copied_size)
          throw_error(capture_store_error_code::source_read_failed, EOVERFLOW,
                      path.string(), "old regular object is too large");
        copied_size += amount;
        continue;
      }
      if (count == 0)
        break;
      if (errno == EINTR)
        continue;
      throw_error(capture_store_error_code::source_read_failed, errno,
                  path.string(), "cannot read old regular object");
    }
    struct stat after {};
    if (::fstat(source.get(), &after) != 0)
      throw_error(capture_store_error_code::source_stat_failed, errno,
                  path.string(), "cannot restat old regular object");
    if (!same_object(opened, after))
      return {backend_operation_outcome::indeterminate, false, std::nullopt};

    std::array<std::uint8_t, 32> digest{};
    unsigned int digest_size = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) != 1 ||
        digest_size != digest.size())
    {
      throw_error(capture_store_error_code::payload_write_failed, EIO,
                  path.string(), "cannot finalize captured payload digest");
    }
    if (!known_matches(object.size(), copied_size) ||
        !known_matches(object.regular_content(),
                       completed_regular_content_identity::parse(
                           digest_text(digest))))
    {
      return {backend_operation_outcome::failed, false, std::nullopt};
    }
    synchronize_fd(payload.descriptor(),
                   capture_store_error_code::payload_sync_failed,
                   "cannot synchronize captured regular payload");
    exact = exact && known(object.size()) && known(object.regular_content());
    regular_payload.emplace(std::move(payload));
    if (after.st_nlink > 1) {
      if (object.hardlink().state() == fact_state::known)
        exact = exact && verify_hardlink(root_fd, object, after);
      else
        exact = false;
    } else if (object.hardlink().state() == fact_state::known) {
      return {backend_operation_outcome::failed, false, std::nullopt};
    }
  } else if (kind == completed_object_kind::symlink) {
    constexpr std::size_t maximum_symlink_size = 1024U * 1024U;
    if (before.st_size > static_cast<off_t>(maximum_symlink_size))
      throw_error(capture_store_error_code::source_read_failed, EOVERFLOW,
                  path.string(), "old symbolic link is too large");
    std::size_t capacity = before.st_size < 0
        ? 256U
        : static_cast<std::size_t>(before.st_size) + 1U;
    capacity = std::min(std::max(capacity, std::size_t{1}), maximum_symlink_size);
    std::vector<char> target(capacity);
    for (;;) {
      const ssize_t count = ::readlinkat(
          leaf.parent.get(), leaf.leaf.c_str(), target.data(), target.size());
      if (count < 0) {
        if (errno == ENOENT)
          return {backend_operation_outcome::indeterminate, false, std::nullopt};
        throw_error(capture_store_error_code::source_read_failed, errno,
                    path.string(), "cannot read old symbolic link");
      }
      if (static_cast<std::size_t>(count) < target.size()) {
        target.resize(static_cast<std::size_t>(count));
        break;
      }
      if (target.size() >= maximum_symlink_size)
        throw_error(capture_store_error_code::source_read_failed, EOVERFLOW,
                    path.string(), "old symbolic link is too large");
      target.resize(std::min(maximum_symlink_size, target.size() * 2U + 1U));
    }
    struct stat after {};
    if (::fstatat(leaf.parent.get(), leaf.leaf.c_str(), &after,
                  AT_SYMLINK_NOFOLLOW) != 0 || !same_object(before, after))
    {
      return {backend_operation_outcome::indeterminate, false, std::nullopt};
    }
    const std::string target_value(target.begin(), target.end());
    if (!known_matches(object.symlink_target(), target_value))
      return {backend_operation_outcome::failed, false, std::nullopt};
    exact = exact && known(object.symlink_target());
  } else {
    struct stat after {};
    if (::fstatat(leaf.parent.get(), leaf.leaf.c_str(), &after,
                  AT_SYMLINK_NOFOLLOW) != 0 || !same_object(before, after))
    {
      return {backend_operation_outcome::indeterminate, false, std::nullopt};
    }
    if (kind == completed_object_kind::character_device ||
        kind == completed_object_kind::block_device)
    {
      const completed_device_number device{
          static_cast<std::uint64_t>(::major(after.st_rdev)),
          static_cast<std::uint64_t>(::minor(after.st_rdev))};
      if (!known_matches(object.device(), device))
        return {backend_operation_outcome::failed, false, std::nullopt};
      exact = exact && known(object.device());
    }
  }

  return {backend_operation_outcome::completed, exact,
          std::move(regular_payload)};
}

unique_fd
open_verified_payload_object(int attempt_fd,
                             const pkgplan::package_path& path,
                             const completed_object_fact& object)
{
  if (object.kind() != completed_object_kind::regular)
    throw_error(capture_store_error_code::object_not_regular, EINVAL,
                path.string(), "captured object is not regular");
  if (!known(object.size()) || !known(object.regular_content()))
    throw_error(capture_store_error_code::payload_mismatch, EINVAL,
                path.string(),
                "captured regular object lacks exact payload facts");

  const std::string name = payload_name(path);
  unique_fd file(open_at(
      attempt_fd, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (file.get() < 0)
    throw_error(capture_store_error_code::payload_open_failed, errno,
                path.string(), "cannot open captured regular payload");
  struct stat before {};
  if (::fstat(file.get(), &before) != 0 || !S_ISREG(before.st_mode) ||
      before.st_size < 0)
  {
    throw_error(capture_store_error_code::payload_mismatch, errno,
                path.string(),
                "captured regular payload has invalid type or size");
  }
  if (static_cast<std::uint64_t>(before.st_size) != *object.size().value())
    throw_error(capture_store_error_code::payload_mismatch, EINVAL,
                path.string(), "captured regular payload size mismatch");

  std::unique_ptr<EVP_MD_CTX, evp_context_deleter> context(EVP_MD_CTX_new());
  if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
    throw_error(capture_store_error_code::payload_mismatch, EIO,
                path.string(), "cannot initialize captured payload digest");
  std::array<std::byte, 64U * 1024U> buffer{};
  for (;;) {
    const ssize_t count = ::read(file.get(), buffer.data(), buffer.size());
    if (count > 0) {
      if (EVP_DigestUpdate(context.get(), buffer.data(),
                           static_cast<std::size_t>(count)) != 1)
      {
        throw_error(capture_store_error_code::payload_mismatch, EIO,
                    path.string(), "cannot update captured payload digest");
      }
      continue;
    }
    if (count == 0)
      break;
    if (errno == EINTR)
      continue;
    throw_error(capture_store_error_code::payload_read_failed, errno,
                path.string(), "cannot read captured regular payload");
  }
  std::array<std::uint8_t, 32> digest{};
  unsigned int digest_size = 0;
  if (EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) != 1 ||
      digest_size != digest.size())
  {
    throw_error(capture_store_error_code::payload_mismatch, EIO,
                path.string(), "cannot finalize captured payload digest");
  }
  struct stat after {};
  if (::fstat(file.get(), &after) != 0 || !same_object(before, after))
    throw_error(capture_store_error_code::payload_mismatch, EIO,
                path.string(),
                "captured regular payload changed while reading");
  if (completed_regular_content_identity::parse(digest_text(digest)) !=
      *object.regular_content().value())
  {
    throw_error(capture_store_error_code::payload_mismatch, EINVAL,
                path.string(), "captured regular payload content mismatch");
  }
  if (::lseek(file.get(), 0, SEEK_SET) < 0)
    throw_error(capture_store_error_code::payload_read_failed, errno,
                path.string(), "cannot rewind captured regular payload");
  return file;
}

unique_fd
open_verified_payload(int attempt_fd,
                      const captured_record& record)
{
  if (!record.observation.object())
    throw_error(capture_store_error_code::payload_mismatch, EINVAL,
                record.request.path().string(),
                "captured regular object lacks its observation");
  return open_verified_payload_object(
      attempt_fd, record.request.path(), *record.observation.object());
}

void
publish_payload(int attempt_fd,
                const pkgplan::package_path& path,
                temporary_capture_file& payload,
                const completed_object_fact& object)
{
  const std::string name = payload_name(path);
  if (::linkat(attempt_fd, payload.name().c_str(),
               attempt_fd, name.c_str(), 0) != 0)
  {
    if (errno != EEXIST)
      throw_error(capture_store_error_code::record_publish_failed, errno,
                  path.string(), "cannot publish captured regular payload");
    static_cast<void>(open_verified_payload_object(attempt_fd, path, object));
  }
  payload.remove();
}

} // namespace

class captured_old_object::implementation final {
public:
  implementation(unique_fd attempt_fd, captured_record record)
      : attempt_fd_(std::move(attempt_fd)), record_(std::move(record)) {}
  unique_fd attempt_fd_;
  captured_record record_;
};

capture_store_error::capture_store_error(
    capture_store_error_code code,
    int system_error,
    std::string path,
    std::string message)
    : std::runtime_error(std::move(message)), code_(code),
      system_error_(system_error), path_(std::move(path))
{
}

capture_store_error_code capture_store_error::code() const noexcept
{ return code_; }
int capture_store_error::system_error() const noexcept
{ return system_error_; }
const std::string& capture_store_error::path() const noexcept
{ return path_; }

captured_regular_object::captured_regular_object(
    int descriptor, std::uint64_t size) noexcept
    : descriptor_(descriptor), size_(size)
{
}
captured_regular_object::captured_regular_object(
    captured_regular_object&& other) noexcept
    : descriptor_(other.descriptor_), size_(other.size_)
{
  other.descriptor_ = -1;
  other.size_ = 0;
}
captured_regular_object& captured_regular_object::operator=(
    captured_regular_object&& other) noexcept
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
captured_regular_object::~captured_regular_object()
{
  if (descriptor_ >= 0)
    static_cast<void>(::close(descriptor_));
}
int captured_regular_object::descriptor() const noexcept
{ return descriptor_; }
std::uint64_t captured_regular_object::size() const noexcept
{ return size_; }

captured_old_object::captured_old_object(
    std::unique_ptr<implementation> state)
    : state_(std::move(state))
{
}
captured_old_object::captured_old_object(captured_old_object&&) noexcept = default;
captured_old_object& captured_old_object::operator=(
    captured_old_object&&) noexcept = default;
captured_old_object::~captured_old_object() = default;
const application_attempt& captured_old_object::attempt() const noexcept
{ return state_->record_.attempt; }
const old_object_capture_request& captured_old_object::request() const noexcept
{ return state_->record_.request; }
const application_path_observation& captured_old_object::observation() const noexcept
{ return state_->record_.observation; }
bool captured_old_object::exact_recovery_possible() const noexcept
{ return state_->record_.exact_recovery_possible; }
captured_regular_object captured_old_object::open_regular() const
{
  unique_fd file = open_verified_payload(state_->attempt_fd_.get(), state_->record_);
  const auto size = *state_->record_.observation.object()->size().value();
  return captured_regular_object(file.release(), size);
}

application_capture_store::application_capture_store(
    int directory_fd, int target_root_fd) noexcept
    : directory_fd_(directory_fd), target_root_fd_(target_root_fd)
{
}

application_capture_store application_capture_store::open(
    const std::string& directory,
    const std::string& target_root)
{
  unique_fd store(open_path(
      directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (store.get() < 0)
    throw capture_store_error(
        capture_store_error_code::directory_open_failed, errno, directory,
        "cannot open private capture directory");
  unique_fd root(open_path(
      target_root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
  if (root.get() < 0)
    throw capture_store_error(
        capture_store_error_code::target_root_open_failed, errno, target_root,
        "cannot open capture target root");
  require_directory(store.get(), capture_store_error_code::directory_invalid,
                    "private capture descriptor is not a directory");
  require_directory(root.get(), capture_store_error_code::target_root_invalid,
                    "capture target root is not a directory");
  return application_capture_store(store.release(), root.release());
}

application_capture_store application_capture_store::from_directory_fds(
    int directory_fd,
    int target_root_fd)
{
  require_directory(directory_fd, capture_store_error_code::directory_invalid,
                    "private capture descriptor is not a directory");
  require_directory(target_root_fd,
                    capture_store_error_code::target_root_invalid,
                    "capture target root is not a directory");
  unique_fd directory_duplicate(duplicate_fd(
      directory_fd, capture_store_error_code::directory_invalid,
      "cannot duplicate private capture descriptor"));
  unique_fd root_duplicate(duplicate_fd(
      target_root_fd, capture_store_error_code::target_root_invalid,
      "cannot duplicate capture target-root descriptor"));
  return application_capture_store(
      directory_duplicate.release(), root_duplicate.release());
}

application_capture_store::application_capture_store(
    application_capture_store&& other) noexcept
    : directory_fd_(other.directory_fd_), target_root_fd_(other.target_root_fd_)
{
  other.directory_fd_ = -1;
  other.target_root_fd_ = -1;
}

application_capture_store& application_capture_store::operator=(
    application_capture_store&& other) noexcept
{
  if (this != &other) {
    if (directory_fd_ >= 0)
      static_cast<void>(::close(directory_fd_));
    if (target_root_fd_ >= 0)
      static_cast<void>(::close(target_root_fd_));
    directory_fd_ = other.directory_fd_;
    target_root_fd_ = other.target_root_fd_;
    other.directory_fd_ = -1;
    other.target_root_fd_ = -1;
  }
  return *this;
}

application_capture_store::~application_capture_store()
{
  if (directory_fd_ >= 0)
    static_cast<void>(::close(directory_fd_));
  if (target_root_fd_ >= 0)
    static_cast<void>(::close(target_root_fd_));
}

std::optional<captured_old_object> application_capture_store::load(
    const application_attempt& attempt,
    const old_object_capture_request& request,
    const application_path_observation& admitted) const
{
  if (directory_fd_ < 0 || target_root_fd_ < 0)
    throw capture_store_error(
        capture_store_error_code::directory_invalid, EBADF, {},
        "private capture store is not open");
  if (admitted.path() != request.path() ||
      admitted.state() != fact_state::known || !admitted.object())
  {
    throw std::invalid_argument(
        "old-object capture binding requires one admitted present path");
  }
  unique_fd attempt_fd = open_attempt_directory(directory_fd_, attempt, false);
  if (attempt_fd.get() < 0)
    return std::nullopt;
  unique_fd lock = lock_attempt(attempt_fd.get(), F_RDLCK);
  const std::string name = record_name(request.path());
  auto bytes = read_file(
      attempt_fd.get(), name, capture_store_error_code::record_read_failed,
      capture_store_error_code::record_read_failed,
      maximum_record_size, true);
  if (bytes.empty())
    return std::nullopt;
  captured_record record = decode_record(bytes, attempt);
  if (record.request.path() != request.path() ||
      record.request.for_rejected_object() != request.for_rejected_object() ||
      record.request.for_recovery() != request.for_recovery() ||
      !same_observation(record.observation, admitted))
  {
    throw capture_store_error(
        capture_store_error_code::binding_mismatch, EINVAL,
        request.path().string(), "private capture object binding mismatch");
  }
  if (record.observation.object()->kind() == completed_object_kind::regular)
    static_cast<void>(open_verified_payload(attempt_fd.get(), record));
  return captured_old_object(std::make_unique<captured_old_object::implementation>(
      std::move(attempt_fd), std::move(record)));
}

old_object_capture_result application_capture_store::capture(
    const application_attempt& attempt,
    const old_object_capture_request& request,
    const application_path_observation& admitted) const
{
  unique_fd attempt_fd = open_attempt_directory(directory_fd_, attempt, true);
  unique_fd lock = lock_attempt(attempt_fd.get(), F_WRLCK);

  // Recheck after taking the exclusive lock.
  const std::string name = record_name(request.path());
  auto existing_bytes = read_file(
      attempt_fd.get(), name, capture_store_error_code::record_read_failed,
      capture_store_error_code::record_read_failed,
      maximum_record_size, true);
  if (!existing_bytes.empty()) {
    captured_record record = decode_record(existing_bytes, attempt);
    if (record.request.path() != request.path() ||
        record.request.for_rejected_object() != request.for_rejected_object() ||
        record.request.for_recovery() != request.for_recovery() ||
        !same_observation(record.observation, admitted))
    {
      throw capture_store_error(
          capture_store_error_code::binding_mismatch, EINVAL,
          request.path().string(), "private capture object binding mismatch");
    }
    if (record.observation.object()->kind() == completed_object_kind::regular)
      static_cast<void>(open_verified_payload(attempt_fd.get(), record));
    return old_object_capture_result(
        backend_operation_outcome::completed, record.observation,
        record.exact_recovery_possible);
  }

  source_capture source = capture_source(
      target_root_fd_, attempt_fd.get(), admitted);
  if (source.outcome != backend_operation_outcome::completed) {
    return old_object_capture_result(
        source.outcome,
        application_path_observation::unknown(request.path()), false);
  }
  if (source.regular_payload)
    publish_payload(attempt_fd.get(), request.path(),
                    *source.regular_payload, *admitted.object());

  captured_record record{
      attempt, request, admitted, source.exact_recovery_possible};
  const auto encoded = encode_record(record);
  publish_immutable_bytes(
      attempt_fd.get(), name, encoded,
      capture_store_error_code::record_write_failed,
      capture_store_error_code::record_write_failed,
      capture_store_error_code::record_publish_failed);

  return old_object_capture_result(
      backend_operation_outcome::completed, admitted,
      source.exact_recovery_possible);
}

void application_capture_store::synchronize(
    const application_attempt& attempt) const
{
  unique_fd attempt_fd = open_attempt_directory(directory_fd_, attempt, false);
  if (attempt_fd.get() < 0)
    throw capture_store_error(
        capture_store_error_code::attempt_invalid, ENOENT, {},
        "private capture attempt does not exist");
  unique_fd lock = lock_attempt(attempt_fd.get(), F_RDLCK);
  synchronize_fd(attempt_fd.get(),
                 capture_store_error_code::namespace_sync_failed,
                 "cannot synchronize private capture attempt");
  synchronize_fd(directory_fd_,
                 capture_store_error_code::namespace_sync_failed,
                 "cannot synchronize private capture namespace");
}

} // namespace pkgapply::posix
