// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "plan_fixture.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <libpkgapply/result.h>

namespace pkgapply::test::application_fixture {

template<class Identity>
[[nodiscard]] inline Identity application_identity(std::uint8_t value)
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

[[nodiscard]] inline application_target_context target()
{
  return application_target_context::make(
      fixture::planning_identity<pkgplan::target_system_context_identity>(1),
      application_identity<managed_target_identity>(2),
      application_identity<root_view_identity>(3),
      application_identity<observation_backend_identity>(4),
      application_identity<mutation_backend_identity>(5),
      application_identity<mutation_exclusion_domain_identity>(6),
      application_identity<active_object_namespace_identity>(7),
      application_identity<rejected_object_store_identity>(8),
      application_identity<staging_namespace_identity>(9),
      application_identity<journal_namespace_identity>(10),
      application_identity<execution_capability_profile_identity>(11));
}

[[nodiscard]] inline application_execution_control control()
{
  return application_execution_control::make(
      application_recovery_requirement::best_effort,
      application_durability_requirement::all_application_domains,
      application_cancellation_policy::recover_after_target_mutation);
}

[[nodiscard]] inline installation_application_request request(
    std::string path = "tool")
{
  const auto context = target();
  const fixture::planning_authorities authorities(context.target());
  return installation_application_request::make(
      fixture::installation_plan(
          authorities,
          {fixture::directory_entry(path)},
          {pkgplan::target_path_observation::absent(
              pkgplan::package_path::parse(path))}),
      fixture::incoming_package({fixture::directory_entry(path)}),
      context,
      control());
}



[[nodiscard]] inline application_attempt_nonce nonce(std::uint8_t seed)
{
  application_attempt_nonce::byte_array bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index)
    bytes[index] = static_cast<std::uint8_t>(seed + index);
  return application_attempt_nonce::from_bytes(bytes);
}

[[nodiscard]] inline application_journal_header journal_header(
    const installation_application_request& application_request,
    std::uint8_t seed = 20)
{
  const auto backend = application_request.target().mutation_backend();
  const auto attempt = application_attempt::make(
      application_request.identity(), application_request.target().identity(),
      backend, nonce(seed));
  const auto lease =
      application_identity<mutation_lease_instance_identity>(seed + 2);
  std::vector<projected_path_owners> projected_paths;
  projected_paths.reserve(
      application_request.plan().preconditions().paths().size());
  for (const auto& expected : application_request.plan().preconditions().paths())
    projected_paths.emplace_back(expected.path(), expected.owners());
  const auto state_projection = lease_bound_state_projection::make(
      lease, application_request.plan().preconditions().installed_snapshot(),
      application_request.plan().preconditions().ownership_inventory(),
      state_projection_completeness::complete, std::move(projected_paths),
      application_identity<state_projection_evidence_identity>(seed + 1));
  return application_journal_header::make(
      pkgplan::operation_kind::install, application_request.identity(),
      application_request.plan().identity(), attempt,
      application_request.target().identity(),
      application_request.control().identity(), state_projection, lease, backend);
}

[[nodiscard]] inline application_durability_profile durability()
{
  using D = application_durability_domain;
  using S = application_durability_status;
  return application_durability_profile({
      {D::journal, S::confirmed},
      {D::incoming_staging, S::confirmed},
      {D::recovery_staging, S::confirmed},
      {D::active_namespace, S::confirmed},
      {D::rejected_object_store, S::confirmed},
      {D::completed_evidence, S::confirmed},
  });
}

[[nodiscard]] inline completed_object_fact directory(
    const pkgplan::package_path& path)
{
  return completed_object_fact(
      path,
      completed_object_kind::directory,
      qualified_fact<std::uint32_t>::known(0755),
      qualified_fact<std::uint64_t>::known(0),
      qualified_fact<std::uint64_t>::known(0),
      qualified_fact<std::uint64_t>::not_applicable(),
      qualified_fact<completed_object_timestamp>::unknown(),
      qualified_fact<completed_regular_content_identity>::not_applicable(),
      qualified_fact<std::string>::not_applicable(),
      qualified_fact<completed_device_number>::not_applicable(),
      qualified_fact<completed_hardlink_relation>::not_applicable(),
      object_fact_provenance::application_observation,
      object_fact_completeness::complete);
}

[[nodiscard]] inline application_path_consequence completed_path(
    const pkgplan::installation_path_decision& decision)
{
  return application_path_consequence(
      decision.path(),
      application_path_role::incoming_entry,
      decision.active(),
      decision.rejected(),
      decision.incoming_entry(),
      decision.ownership(),
      application_effect_status::completed,
      application_effect_status::not_attempted,
      application_path_observation::absent(decision.path()),
      application_path_observation::present(directory(decision.path())),
      std::nullopt,
      ownership_publication_status::eligible);
}

[[nodiscard]] inline completed_application_evidence completed_evidence(
    const installation_application_request& application_request,
    const application_journal_header& header,
    std::uint8_t seed = 20)
{
  return completed_application_evidence::installation(
      application_request, header.attempt().identity(),
      header.state_projection(), header.identity(),
      {completed_path(application_request.plan().paths().front())}, durability(),
      {application_identity<application_backend_evidence_identity>(seed + 3)});
}

} // namespace pkgapply::test::application_fixture
