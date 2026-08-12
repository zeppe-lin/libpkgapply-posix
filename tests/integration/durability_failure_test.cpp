// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "checkpoint_test_fixture.h"

#include <libpkgapply-posix/backend.h>
#include <libpkgapply/capture.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

std::atomic<bool> fail_next_fsync{false};

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
    std::array<char, 96> pattern{};
    constexpr std::string_view seed =
        "/tmp/libpkgapply-posix-durability-XXXXXX";
    std::memcpy(pattern.data(), seed.data(), seed.size());
    char* value = ::mkdtemp(pattern.data());
    if (value == nullptr) {
      throw std::runtime_error("cannot create durability test directory");
    }
    path_ = value;
  }

  ~temporary_directory()
  {
    const std::string command = "rm -rf -- '" + path_ + "'";
    static_cast<void>(std::system(command.c_str()));
  }

  [[nodiscard]] const std::string& path() const noexcept
  {
    return path_;
  }

private:
  std::string path_;
};

void make_directory(const std::string& path, mode_t mode = 0700)
{
  require(::mkdir(path.c_str(), mode) == 0,
          "cannot create durability test directory component");
}

int open_directory(const std::string& path)
{
  const int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  require(fd >= 0, "cannot open durability test directory");
  return fd;
}

class fake_lease final : public pkgapply::target_mutation_lease {
public:
  fake_lease(pkgapply::mutation_lease_instance_identity identity,
             pkgapply::application_target_context_identity target,
             pkgapply::mutation_exclusion_domain_identity domain)
      : identity_(std::move(identity)),
        target_(std::move(target)),
        domain_(std::move(domain))
  {
  }

  [[nodiscard]] const pkgapply::mutation_lease_instance_identity&
  identity() const noexcept override
  {
    return identity_;
  }

  [[nodiscard]] const pkgapply::application_target_context_identity&
  target() const noexcept override
  {
    return target_;
  }

  [[nodiscard]] const pkgapply::mutation_exclusion_domain_identity&
  exclusion_domain() const noexcept override
  {
    return domain_;
  }

  [[nodiscard]] bool held() const noexcept override
  {
    return true;
  }

private:
  pkgapply::mutation_lease_instance_identity identity_;
  pkgapply::application_target_context_identity target_;
  pkgapply::mutation_exclusion_domain_identity domain_;
};

class backend_layout final {
public:
  explicit backend_layout(std::uint8_t lease_seed)
      : target_(pkgapply::test::checkpoint_fixture::target()),
        lease_(pkgapply::test::checkpoint_fixture::application_identity<
                   pkgapply::mutation_lease_instance_identity>(lease_seed),
               target_.identity(), target_.mutation_exclusion_domain())
  {
    make_directory(root_.path() + "/target");
    for (const auto* name : {
             "journal", "checkpoint", "payload", "capture", "rejected",
             "completed"}) {
      make_directory(root_.path() + "/" + name);
    }

    std::array<int, 7> descriptors = {
        open_directory(root_.path() + "/target"),
        open_directory(root_.path() + "/journal"),
        open_directory(root_.path() + "/checkpoint"),
        open_directory(root_.path() + "/payload"),
        open_directory(root_.path() + "/capture"),
        open_directory(root_.path() + "/rejected"),
        open_directory(root_.path() + "/completed"),
    };
    backend_ = pkgapply::posix::application_posix_backend::from_directory_fds(
        target_, descriptors[0], descriptors[1], descriptors[2], descriptors[3],
        descriptors[4], descriptors[5], descriptors[6]);
    for (const int descriptor : descriptors) {
      require(::close(descriptor) == 0, "cannot close caller descriptor");
    }
  }

  [[nodiscard]] const pkgapply::application_target_context&
  target() const noexcept
  {
    return target_;
  }

  [[nodiscard]] fake_lease& lease() noexcept
  {
    return lease_;
  }

  [[nodiscard]] pkgapply::posix::application_posix_backend& backend() noexcept
  {
    return *backend_;
  }

  [[nodiscard]] const std::string& root_path() const noexcept
  {
    return root_.path();
  }

private:
  temporary_directory root_;
  pkgapply::application_target_context target_;
  fake_lease lease_;
  std::unique_ptr<pkgapply::posix::application_posix_backend> backend_;
};

void observe_preconditions(
    pkgapply::application_backend_transaction& transaction,
    const pkgplan::operation_preconditions& preconditions)
{
  std::vector<pkgplan::package_path> paths;
  for (const auto& expected : preconditions.paths()) {
    paths.push_back(expected.path());
  }
  const auto observed = transaction.observe(paths);
  require(observed.requested() == paths,
          "durability fixture did not admit the exact precondition closure");
}

template<class Request>
pkgapply::application_journal_record publish_preparing_journal(
    pkgapply::application_backend_transaction& transaction,
    const Request& request,
    const fake_lease& lease,
    std::uint8_t state_projection_seed)
{
  const auto attempt = pkgapply::application_attempt::make(
      request.identity(), request.target().identity(), transaction.backend(),
      transaction.attempt_nonce());
  std::vector<pkgapply::projected_path_owners> projected_paths;
  projected_paths.reserve(request.plan().preconditions().paths().size());
  for (const auto& expected : request.plan().preconditions().paths()) {
    projected_paths.emplace_back(expected.path(), expected.owners());
  }
  const auto state_projection = pkgapply::lease_bound_state_projection::make(
      lease.identity(), request.plan().preconditions().installed_snapshot(),
      request.plan().preconditions().ownership_inventory(),
      pkgapply::state_projection_completeness::complete,
      std::move(projected_paths),
      pkgapply::test::checkpoint_fixture::application_identity<
          pkgapply::state_projection_evidence_identity>(state_projection_seed));
  const auto header = pkgapply::application_journal_header::make(
      request.plan().kind(), request.identity(), request.plan().identity(),
      attempt, request.target().identity(), request.control().identity(),
      state_projection, lease.identity(), transaction.backend());
  return transaction.publish_journal(pkgapply::application_journal_record::make(
      header, pkgapply::application_journal_state::preparing, {}, {}));
}

void expect_unconfirmed_then_retry(
    pkgapply::application_backend_transaction& transaction,
    pkgapply::application_durability_domain domain,
    std::string_view label)
{
  fail_next_fsync.store(true, std::memory_order_relaxed);
  const auto failed = transaction.synchronize(domain);
  require(failed.domain() == domain &&
              failed.status() ==
                  pkgapply::application_durability_status::unconfirmed,
          std::string(label) +
              " fsync failure escaped instead of reporting unconfirmed "
              "durability");

  const auto retried = transaction.synchronize(domain);
  require(retried.domain() == domain &&
              retried.status() ==
                  pkgapply::application_durability_status::confirmed,
          std::string(label) +
              " durability could not be retried after an unconfirmed fsync");
}

pkgimage::package_entry regular_entry(std::string path)
{
  pkgimage::package_entry entry(
      pkgimage::package_path::parse(std::move(path)),
      pkgimage::entry_type::regular);
  entry.mode = 0644;
  entry.uid = 0;
  entry.gid = 0;
  entry.size = 4;
  entry.regular_content = pkgimage::regular_content_digest::parse(
      "v1:sha256:3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb"
      "23adc8b7");
  return entry;
}

void test_journal_durability_failure()
{
  backend_layout layout(70);
  const auto request = pkgapply::test::checkpoint_fixture::request("journal");
  const pkgimage::package_image image({
      pkgapply::test::fixture::directory_entry("journal"),
  });
  auto transaction = layout.backend().begin_with_incoming_image(
      pkgapply::package_application_request(request), layout.lease(), image);
  observe_preconditions(*transaction, request.plan().preconditions());
  static_cast<void>(publish_preparing_journal(
      *transaction, request, layout.lease(), 71));

  expect_unconfirmed_then_retry(
      *transaction, pkgapply::application_durability_domain::journal,
      "journal");
}

void test_incoming_staging_durability_failure()
{
  backend_layout layout(80);
  const auto entry = regular_entry("incoming");
  const auto authorities =
      pkgapply::test::fixture::planning_authorities(layout.target().target());
  const auto path = pkgplan::package_path::parse("incoming");
  const auto digest = pkgapply::test::fixture::archive_digest(81);
  const auto plan = pkgapply::test::fixture::installation_plan(
      authorities, {entry}, {pkgplan::target_path_observation::absent(path)},
      {}, std::nullopt, digest);
  const auto request = pkgapply::installation_application_request::make(
      plan, pkgapply::test::fixture::incoming_package({entry}, digest),
      layout.target(), pkgapply::test::checkpoint_fixture::control());
  const pkgimage::package_image image({entry});
  auto transaction = layout.backend().begin_with_incoming_image(
      pkgapply::package_application_request(request), layout.lease(), image);
  observe_preconditions(*transaction, request.plan().preconditions());

  const auto selection = pkgimage::entry_selection::all_regular(image);
  auto stage = transaction->begin_payload_stage(image, selection);
  constexpr std::string_view bytes = "data";
  stage->begin(image.entries().front());
  stage->write(
      image.entries().front(),
      reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  stage->end(image.entries().front());
  require(stage->seal().outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "incoming durability fixture did not seal payload staging");

  expect_unconfirmed_then_retry(
      *transaction, pkgapply::application_durability_domain::incoming_staging,
      "incoming staging");
}

void test_recovery_staging_durability_failure()
{
  backend_layout layout(90);
  const auto path = pkgplan::package_path::parse("old");
  make_directory(layout.root_path() + "/target/old", 0755);
  const auto authorities =
      pkgapply::test::fixture::planning_authorities(layout.target().target());
  const auto object = pkgapply::test::fixture::directory_object(0755);
  const auto plan = pkgapply::test::fixture::removal_plan(
      authorities,
      {pkgplan::installed_ownership_claim(
          path, authorities.installed_package, object)},
      {pkgplan::target_path_observation::present(
          pkgplan::filesystem_object_fact(path, object))});
  const auto request = pkgapply::removal_application_request::make(
      plan, layout.target(), pkgapply::test::checkpoint_fixture::control());
  auto transaction = layout.backend().begin_without_incoming_image(
      pkgapply::package_application_request(request), layout.lease());
  observe_preconditions(*transaction, request.plan().preconditions());

  const auto captures = pkgapply::prepare_old_object_captures(
      request.plan(), request.control());
  const auto* capture = captures.find(path);
  require(capture != nullptr && capture->for_recovery(),
          "recovery durability fixture lacks capture authority");
  require(transaction->capture_old(*capture).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "recovery durability fixture did not capture prior target authority");

  expect_unconfirmed_then_retry(
      *transaction, pkgapply::application_durability_domain::recovery_staging,
      "recovery staging");
}

void test_rejected_store_durability_failure()
{
  backend_layout layout(100);
  const auto path = pkgplan::package_path::parse("rejected");
  const auto entry = pkgapply::test::fixture::directory_entry("rejected");
  const auto authorities =
      pkgapply::test::fixture::planning_authorities(layout.target().target());
  const auto digest = pkgapply::test::fixture::archive_digest(101);
  const auto policy = pkgapply::test::fixture::policy_snapshot(
      authorities,
      pkgapply::test::fixture::path_policy(
          pkgplan::incoming_path_policy::retain(
              pkgplan::rejected_object_policy::stage,
              pkgplan::retained_active_ownership_policy::
                  do_not_claim_operated_package)));
  const auto plan = pkgapply::test::fixture::installation_plan(
      authorities, {entry}, {pkgplan::target_path_observation::absent(path)},
      {}, policy, digest);
  const auto request = pkgapply::installation_application_request::make(
      plan, pkgapply::test::fixture::incoming_package({entry}, digest),
      layout.target(), pkgapply::test::checkpoint_fixture::control());
  const pkgimage::package_image image({entry});
  auto transaction = layout.backend().begin_with_incoming_image(
      pkgapply::package_application_request(request), layout.lease(), image);
  observe_preconditions(*transaction, request.plan().preconditions());

  const auto rejected = pkgapply::test::fixture::rejected_request(plan, path);
  require(transaction->execute_rejected(rejected).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "rejected durability fixture did not publish rejected authority");

  expect_unconfirmed_then_retry(
      *transaction,
      pkgapply::application_durability_domain::rejected_object_store,
      "rejected store");
}

void test_completed_evidence_durability_failure()
{
  backend_layout layout(110);
  const auto request = pkgapply::test::checkpoint_fixture::request("completed");
  const pkgimage::package_image image({
      pkgapply::test::fixture::directory_entry("completed"),
  });
  auto transaction = layout.backend().begin_with_incoming_image(
      pkgapply::package_application_request(request), layout.lease(), image);
  observe_preconditions(*transaction, request.plan().preconditions());
  const auto journal = publish_preparing_journal(
      *transaction, request, layout.lease(), 111);
  const auto attempt = pkgapply::application_attempt::make(
      request.identity(), request.target().identity(), transaction->backend(),
      transaction->attempt_nonce());
  const auto evidence = pkgapply::completed_application_evidence::installation(
      request, attempt.identity(), journal.header().state_projection(),
      journal.header().identity(),
      {pkgapply::test::checkpoint_fixture::completed_path(
          request.plan().paths().front())},
      pkgapply::test::checkpoint_fixture::durability());
  require(transaction->publish_completed_evidence(evidence).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "completed durability fixture did not publish evidence authority");

  expect_unconfirmed_then_retry(
      *transaction, pkgapply::application_durability_domain::completed_evidence,
      "completed evidence");
}

} // namespace

extern "C" int fsync(int descriptor)
{
  if (fail_next_fsync.exchange(false, std::memory_order_relaxed)) {
    errno = EIO;
    return -1;
  }
  return static_cast<int>(::syscall(SYS_fsync, descriptor));
}

int main()
{
  test_journal_durability_failure();
  test_incoming_staging_durability_failure();
  test_recovery_staging_durability_failure();
  test_rejected_store_durability_failure();
  test_completed_evidence_durability_failure();
  return 0;
}
