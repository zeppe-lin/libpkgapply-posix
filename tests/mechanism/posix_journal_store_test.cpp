// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "nonblocking_refusal.h"

#include <libpkgapply-posix/journal_store.h>
#include <libpkgapply/journal_transport_codec.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fcntl.h>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

void require(bool condition, std::string_view message)
{
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

template<class Identity>
Identity application_identity(std::uint8_t value)
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
Identity planning_identity(std::uint8_t value)
{
  std::array<std::uint8_t, 32> bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index)
    bytes[index] = static_cast<std::uint8_t>(value + index);
  return Identity::from_sha256(bytes);
}

pkgapply::lease_bound_state_projection state_projection(std::uint8_t seed)
{
  const auto lease = application_identity<
      pkgapply::mutation_lease_instance_identity>(seed + 6);
  return pkgapply::lease_bound_state_projection::make(
      lease,
      planning_identity<pkgplan::installed_state_snapshot_identity>(seed + 5),
      planning_identity<pkgplan::ownership_inventory_identity>(seed + 7),
      pkgapply::state_projection_completeness::complete,
      {pkgapply::projected_path_owners(
          pkgplan::package_path::parse("usr/bin/tool"),
          {planning_identity<pkgplan::installed_package_identity>(seed + 9)})},
      application_identity<pkgapply::state_projection_evidence_identity>(
          seed + 8));
}

pkgapply::application_journal_header header(std::uint8_t request_seed = 1,
                                            std::uint8_t attempt_seed = 1)
{
  pkgapply::application_attempt_nonce::byte_array nonce{};
  for (std::size_t index = 0; index < nonce.size(); ++index)
    nonce[index] = static_cast<std::uint8_t>(attempt_seed + 20 + index);
  const auto request =
      application_identity<pkgapply::application_request_identity>(request_seed);
  const auto target = application_identity<
      pkgapply::application_target_context_identity>(request_seed + 1);
  const auto backend =
      application_identity<pkgapply::mutation_backend_identity>(request_seed + 2);
  const auto attempt = pkgapply::application_attempt::make(
      request, target, backend,
      pkgapply::application_attempt_nonce::from_bytes(nonce));
  const auto projection = state_projection(request_seed);
  return pkgapply::application_journal_header::make(
      pkgplan::operation_kind::install, request,
      planning_identity<pkgplan::operation_plan_identity>(request_seed + 3),
      attempt, target,
      application_identity<
          pkgapply::application_execution_control_identity>(request_seed + 4),
      projection, projection.lease(), backend);
}

std::vector<pkgapply::application_journal_effect> effects()
{
  return {pkgapply::application_journal_effect::make(
      0, pkgapply::application_journal_effect_kind::publish_active_object,
      pkgplan::package_path::parse("usr/bin/tool"))};
}

pkgapply::application_journal_declaration declaration(
    std::uint8_t request_seed = 1,
    std::uint8_t attempt_seed = 1)
{
  return pkgapply::application_journal_declaration::make(
      header(request_seed, attempt_seed), effects(),
      {std::byte{0x00}, std::byte{0x7f}, std::byte{0x80}, std::byte{0xff}});
}

std::string suffix(std::string_view identity)
{
  constexpr std::string_view prefix = "v1:sha256:";
  require(identity.size() == prefix.size() + 64 &&
              identity.substr(0, prefix.size()) == prefix,
          "test identity has unexpected representation");
  return std::string(identity.substr(prefix.size()));
}

std::string journal_directory(
    const std::string& root,
    const pkgapply::application_journal_declaration_identity& identity)
{
  return root + "/journal-v1-sha256-" + suffix(identity.string());
}

std::string step_file(std::uint64_t sequence)
{
  std::string digits = std::to_string(sequence);
  return std::string(20U - digits.size(), '0') + digits + ".bin";
}

std::uint64_t regular_bytes(const std::filesystem::path& root)
{
  std::uint64_t result = 0;
  for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
    const auto status = entry.symlink_status();
    if (std::filesystem::is_regular_file(status))
      result += static_cast<std::uint64_t>(std::filesystem::file_size(entry.path()));
  }
  return result;
}

bool has_temporary_name(const std::filesystem::path& root)
{
  for (const auto& entry : std::filesystem::recursive_directory_iterator(root))
    if (entry.path().filename().string().find(".tmp.") != std::string::npos)
      return true;
  return false;
}

void replace_with_bytes(const std::string& path, std::string_view bytes)
{
  const int fd = ::open(path.c_str(), O_WRONLY | O_TRUNC | O_NOFOLLOW);
  require(fd >= 0, "cannot open journal value for corruption test");
  require(::write(fd, bytes.data(), bytes.size()) ==
              static_cast<ssize_t>(bytes.size()),
          "cannot corrupt journal value");
  require(::close(fd) == 0, "cannot close corrupted journal value");
}

} // namespace

int main()
{
  char root_template[] = "/tmp/libpkgapply-journal-store-XXXXXX";
  char* root_value = ::mkdtemp(root_template);
  require(root_value != nullptr, "cannot create journal-store test root");
  const std::string root = root_value;
  const std::string directory = root + "/journal";
  const std::string moved = root + "/moved";
  const std::string link = root + "/link";
  require(::mkdir(directory.c_str(), 0700) == 0,
          "cannot create journal-store test directory");

  auto store = pkgapply::posix::application_journal_store::open(directory);
  int directory_fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY);
  require(directory_fd >= 0, "cannot open journal-store test descriptor");
  auto duplicated =
      pkgapply::posix::application_journal_store::from_directory_fd(directory_fd);
  require(::close(directory_fd) == 0,
          "cannot close original journal-store test descriptor");

  const auto declared = declaration();
  require(store->publish_declaration(declared).identity() == declared.identity(),
          "journal store changed immutable declaration authority");
  require(store->publish_declaration(declared).identity() == declared.identity(),
          "journal store rejected exact declaration republication");
  const auto loaded_declaration = store->load_declaration(declared.identity());
  require(loaded_declaration &&
              loaded_declaration->identity() == declared.identity() &&
              loaded_declaration->replay_seed() == declared.replay_seed(),
          "journal store did not load exact owner declaration bytes");
  require(duplicated->load_declaration(declared.identity()).has_value(),
          "duplicated journal-store descriptor lost authority");
  require(!store->load_declaration(declaration(9).identity()),
          "journal store invented an unknown declaration");
  const auto active = store->load_active_declaration(declared.header().request());
  require(active && *active == declared.identity(),
          "journal store did not publish direct request locator");

  auto cursor = pkgapply::application_journal_cursor::initial(declared);
  require(store->compare_and_publish_cursor(std::nullopt, cursor).identity() ==
              cursor.identity(),
          "journal store did not publish initial bounded cursor");
  require(store->load_cursor(declared.identity())->identity() == cursor.identity(),
          "journal store did not load initial bounded cursor");

  const auto prepared = pkgapply::application_journal_step::make(
      declared.identity(), 0, std::nullopt,
      pkgapply::application_journal_state::prepared);
  require(store->publish_step(prepared).identity() == prepared.identity(),
          "journal store changed immutable preparation step");
  require(store->publish_step(prepared).identity() == prepared.identity(),
          "journal store rejected exact immutable step republication");
  require(store->load_step(declared.identity(), 0)->identity() ==
              prepared.identity(),
          "journal store did not load exact step zero");

  // Crash after immutable step durability but before cursor replacement.
  require(store->load_cursor(declared.identity())->step_count() == 0,
          "orphan step publication advanced the bounded cursor");
  const auto advanced = pkgapply::application_journal_cursor::advance(cursor, prepared);
  require(store->compare_and_publish_cursor(cursor.identity(), advanced).identity() ==
              advanced.identity(),
          "journal store did not compare-and-publish the next cursor");
  // Exact retry is valid after a caller observed a publication-visibility error.
  require(store->compare_and_publish_cursor(cursor.identity(), advanced).identity() ==
              advanced.identity(),
          "journal store rejected exact cursor retry");
  cursor = advanced;

  bool rejected = false;
  try {
    const auto stale = pkgapply::application_journal_cursor::initial(declared);
    static_cast<void>(
        store->compare_and_publish_cursor(stale.identity(), stale));
  } catch (const pkgapply::posix::journal_store_error& error) {
    rejected = error.code() ==
        pkgapply::posix::journal_store_error_code::cursor_conflict;
  }
  require(rejected, "journal store accepted stale cursor CAS authority");

  // Cross-process CAS must serialize the complete read/compare/replace
  // sequence. Two writers start from the same expected cursor and propose
  // different valid successors; exactly one may commit.
  const auto race_declared = declaration(40, 40);
  static_cast<void>(store->publish_declaration(race_declared));
  auto race_cursor = pkgapply::application_journal_cursor::initial(race_declared);
  static_cast<void>(store->compare_and_publish_cursor(std::nullopt, race_cursor));
  const auto race_prepared = pkgapply::application_journal_step::make(
      race_declared.identity(), 0, std::nullopt,
      pkgapply::application_journal_state::prepared);
  static_cast<void>(store->publish_step(race_prepared));
  auto race_prepared_cursor =
      pkgapply::application_journal_cursor::advance(race_cursor, race_prepared);
  static_cast<void>(store->compare_and_publish_cursor(
      race_cursor.identity(), race_prepared_cursor));
  const auto race_effect = race_declared.effects().front();
  const auto race_intent = pkgapply::application_journal_step::make(
      race_declared.identity(), 1, race_prepared.identity(),
      pkgapply::application_journal_state::mutating,
      pkgapply::application_journal_event(
          0, pkgapply::application_journal_event_kind::intent,
          race_effect.identity()));
  static_cast<void>(store->publish_step(race_intent));
  const auto race_intent_cursor =
      pkgapply::application_journal_cursor::advance(
          race_prepared_cursor, race_intent);
  static_cast<void>(store->compare_and_publish_cursor(
      race_prepared_cursor.identity(), race_intent_cursor));

  const auto race_terminal_a = pkgapply::application_journal_step::make(
      race_declared.identity(), 2, race_intent.identity(),
      pkgapply::application_journal_state::effects_visible,
      pkgapply::application_journal_event(
          1, pkgapply::application_journal_event_kind::completed,
          race_effect.identity(),
          {application_identity<pkgapply::application_backend_evidence_identity>(90)}),
      {std::byte{0x01}});
  const auto race_terminal_b = pkgapply::application_journal_step::make(
      race_declared.identity(), 2, race_intent.identity(),
      pkgapply::application_journal_state::effects_visible,
      pkgapply::application_journal_event(
          1, pkgapply::application_journal_event_kind::completed,
          race_effect.identity(),
          {application_identity<pkgapply::application_backend_evidence_identity>(91)}),
      {std::byte{0x02}});
  const auto race_cursor_a = pkgapply::application_journal_cursor::advance(
      race_intent_cursor, race_terminal_a);
  const auto race_cursor_b = pkgapply::application_journal_cursor::advance(
      race_intent_cursor, race_terminal_b);
  require(race_cursor_a.identity() != race_cursor_b.identity(),
          "journal CAS race did not construct competing cursor values");

  int start_pipe[2] {-1, -1};
  require(::pipe(start_pipe) == 0, "cannot create journal CAS race barrier");
  const auto spawn_writer = [&](const pkgapply::application_journal_cursor& desired) {
    const pid_t child = ::fork();
    require(child >= 0, "cannot fork journal CAS race writer");
    if (child == 0) {
      static_cast<void>(::close(start_pipe[1]));
      char token = 0;
      if (::read(start_pipe[0], &token, 1) != 1)
        ::_exit(12);
      try {
        static_cast<void>(store->compare_and_publish_cursor(
            race_intent_cursor.identity(), desired));
        ::_exit(0);
      }
      catch (const pkgapply::posix::journal_store_error& error) {
        ::_exit(error.code() ==
                    pkgapply::posix::journal_store_error_code::cursor_conflict
                ? 10
                : 11);
      }
      catch (...) {
        ::_exit(11);
      }
    }
    return child;
  };
  const pid_t race_a = spawn_writer(race_cursor_a);
  const pid_t race_b = spawn_writer(race_cursor_b);
  require(::close(start_pipe[0]) == 0,
          "cannot close parent journal CAS race read end");
  const char tokens[2] {'a', 'b'};
  require(::write(start_pipe[1], tokens, sizeof(tokens)) ==
              static_cast<ssize_t>(sizeof(tokens)),
          "cannot release journal CAS race writers");
  require(::close(start_pipe[1]) == 0,
          "cannot close parent journal CAS race write end");
  int status_a = 0;
  int status_b = 0;
  require(::waitpid(race_a, &status_a, 0) == race_a &&
              ::waitpid(race_b, &status_b, 0) == race_b,
          "cannot reap journal CAS race writers");
  require(WIFEXITED(status_a) && WIFEXITED(status_b),
          "journal CAS race writer did not exit normally");
  const int result_a = WEXITSTATUS(status_a);
  const int result_b = WEXITSTATUS(status_b);
  require((result_a == 0 && result_b == 10) ||
              (result_a == 10 && result_b == 0),
          "journal cursor CAS admitted zero or multiple cross-process writers");
  const auto raced = store->load_cursor(race_declared.identity());
  require(raced &&
              (raced->identity() == race_cursor_a.identity() ||
               raced->identity() == race_cursor_b.identity()),
          "journal CAS race retained neither committed cursor");

  const auto graph = declared.effects();
  const auto intent = pkgapply::application_journal_step::make(
      declared.identity(), 1, prepared.identity(),
      pkgapply::application_journal_state::mutating,
      pkgapply::application_journal_event(
          0, pkgapply::application_journal_event_kind::intent,
          graph[0].identity()));
  static_cast<void>(store->publish_step(intent));
  const auto intent_cursor =
      pkgapply::application_journal_cursor::advance(cursor, intent);
  static_cast<void>(
      store->compare_and_publish_cursor(cursor.identity(), intent_cursor));
  cursor = intent_cursor;

  const auto conflicting = pkgapply::application_journal_step::make(
      declared.identity(), 1, prepared.identity(),
      pkgapply::application_journal_state::prepared);
  rejected = false;
  try {
    static_cast<void>(store->publish_step(conflicting));
  } catch (const pkgapply::posix::journal_store_error& error) {
    rejected = error.code() ==
        pkgapply::posix::journal_store_error_code::immutable_conflict;
  }
  require(rejected, "journal store replaced an immutable exact-sequence step");

  // Assault descriptor and byte cardinality with an append-only physical chain.
  struct rlimit previous_limit {};
  require(::getrlimit(RLIMIT_NOFILE, &previous_limit) == 0,
          "cannot read descriptor limit");
  struct rlimit constrained = previous_limit;
  constrained.rlim_cur = std::min<rlim_t>(previous_limit.rlim_cur, 48);
  require(::setrlimit(RLIMIT_NOFILE, &constrained) == 0,
          "cannot constrain descriptor limit");

  std::uint64_t expected_bytes =
      pkgapply::encode_application_journal_declaration(declared).size() +
      pkgapply::encode_application_journal_cursor(cursor).size();
  expected_bytes += pkgapply::encode_application_journal_step(prepared).size();
  expected_bytes += pkgapply::encode_application_journal_step(intent).size();
  auto predecessor = intent.identity();
  constexpr std::uint64_t scale_steps = 512;
  for (std::uint64_t index = 0; index < scale_steps; ++index) {
    const auto step = pkgapply::application_journal_step::make(
        declared.identity(), index + 2, predecessor,
        pkgapply::application_journal_state::mutating);
    static_cast<void>(store->publish_step(step));
    expected_bytes += pkgapply::encode_application_journal_step(step).size();
    predecessor = step.identity();
  }
  require(::setrlimit(RLIMIT_NOFILE, &previous_limit) == 0,
          "cannot restore descriptor limit");

  const auto journal_path = journal_directory(directory, declared.identity());
  require(regular_bytes(journal_path) == expected_bytes,
          "journal store retained bytes outside declaration + steps + bounded cursor");
  require(!has_temporary_name(journal_path),
          "journal store left temporary publication names behind");
  require(std::filesystem::exists(journal_path + "/steps/" +
                                  step_file(scale_steps + 1)),
          "journal store did not retain the final exact sequence step");

  const auto second_attempt = declaration(1, 31);
  require(second_attempt.identity() != declared.identity(),
          "journal-store test did not construct a distinct attempt");
  static_cast<void>(store->publish_declaration(second_attempt));
  const auto active_second =
      store->load_active_declaration(second_attempt.header().request());
  require(active_second && *active_second == second_attempt.identity(),
          "journal store did not advance direct request locator");
  require(store->load_declaration(declared.identity()).has_value(),
          "journal store removed historical immutable declaration authority");

  require(::rename(directory.c_str(), moved.c_str()) == 0,
          "cannot rename journal-store root");
  require(store->load_declaration(declared.identity()).has_value() &&
              duplicated->load_declaration(declared.identity()).has_value(),
          "journal store lost descriptor anchor after pathname replacement");
  require(::symlink(moved.c_str(), link.c_str()) == 0,
          "cannot create journal-store root symlink");
  rejected = false;
  try {
    static_cast<void>(pkgapply::posix::application_journal_store::open(link));
  } catch (const pkgapply::posix::journal_store_error& error) {
    rejected = error.code() ==
        pkgapply::posix::journal_store_error_code::directory_open_failed;
  }
  require(rejected, "journal store followed a root-directory symlink");

  const auto moved_journal = journal_directory(moved, declared.identity());
  replace_with_bytes(moved_journal + "/declaration.bin", "corrupt");
  rejected = false;
  try {
    static_cast<void>(store->load_declaration(declared.identity()));
  } catch (const pkgapply::posix::journal_store_error& error) {
    rejected = error.code() ==
        pkgapply::posix::journal_store_error_code::value_corrupt;
  }
  require(rejected, "journal store accepted corrupt declaration bytes");

  const std::string cursor_path = moved_journal + "/cursor.bin";
  require(pkgapply::test::replace_with_fifo(cursor_path),
          "cannot replace bounded cursor with fifo");
  require(pkgapply::test::refuses_without_blocking([&]() {
    try {
      static_cast<void>(store->load_cursor(declared.identity()));
    } catch (const pkgapply::posix::journal_store_error& error) {
      return error.code() ==
          pkgapply::posix::journal_store_error_code::value_corrupt;
    }
    return false;
  }), "journal store blocked on special-file cursor corruption");

  store.reset();
  duplicated.reset();
  require(::unlink(link.c_str()) == 0,
          "cannot remove journal-store root symlink");
  std::filesystem::remove_all(moved);
  require(::rmdir(root.c_str()) == 0,
          "cannot remove journal-store test root");
  return 0;
}
