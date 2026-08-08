// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "plan_fixture.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <libpkgapply/restart.h>

namespace pkgapply::test::checkpoint_fixture {

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

[[nodiscard]] inline application_journal_record journal(
    const installation_application_request& application_request,
    std::uint8_t seed = 20)
{
  const auto path = application_request.plan().paths().front().path();
  const auto backend = application_request.target().mutation_backend();
  const auto attempt = application_attempt::make(
      application_request.identity(),
      application_request.target().identity(),
      backend,
      nonce(seed));
  const auto state_projection =
      application_identity<lease_bound_state_projection_identity>(seed + 1);
  const auto header = application_journal_header::make(
      pkgplan::operation_kind::install,
      application_request.identity(),
      application_request.plan().identity(),
      attempt,
      application_request.target().identity(),
      application_request.control().identity(),
      state_projection,
      application_identity<mutation_lease_instance_identity>(seed + 2),
      backend);
  const std::vector<application_journal_effect> effects = {
      application_journal_effect::make(
          0, application_journal_effect_kind::stage_incoming_payload, path),
      application_journal_effect::make(
          1, application_journal_effect_kind::publish_active_object, path),
  };
  return application_journal_record::make(
      header,
      application_journal_state::effects_visible,
      effects,
      {
          {0, application_journal_event_kind::intent, effects[0].identity()},
          {1, application_journal_event_kind::completed, effects[0].identity()},
          {2, application_journal_event_kind::intent, effects[1].identity()},
          {3, application_journal_event_kind::completed, effects[1].identity()},
      });
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

[[nodiscard]] inline application_restart_checkpoint checkpoint(
    const installation_application_request& application_request,
    const application_journal_record& application_journal,
    std::uint8_t seed = 20)
{
  const auto& decision = application_request.plan().paths().front();
  const auto path = decision.path();
  const auto completed = completed_application_evidence::installation(
      application_request,
      application_journal.header().attempt().identity(),
      application_journal.header().state_projection(),
      application_journal.header().identity(),
      {completed_path(decision)},
      durability(),
      {application_identity<application_backend_evidence_identity>(seed + 3)});

  return application_restart_checkpoint::make(
      application_journal.identity(),
      backend_observation_batch::make(
          {path},
          {application_path_observation::absent(path)},
          {application_identity<application_backend_evidence_identity>(seed + 5)}),
      backend_operation_result(
          backend_operation_outcome::completed,
          {application_identity<application_backend_evidence_identity>(seed + 6)}),
      {},
      {},
      {application_restart_active_effect(
          path,
          backend_operation_result(
              backend_operation_outcome::completed,
              {application_identity<application_backend_evidence_identity>(
                  seed + 7)}))},
      {},
      {
          application_restart_synchronization(application_durability_fact(
              application_durability_domain::journal,
              application_durability_status::confirmed)),
          application_restart_synchronization(application_durability_fact(
              application_durability_domain::incoming_staging,
              application_durability_status::confirmed)),
          application_restart_synchronization(application_durability_fact(
              application_durability_domain::recovery_staging,
              application_durability_status::confirmed)),
          application_restart_synchronization(application_durability_fact(
              application_durability_domain::active_namespace,
              application_durability_status::confirmed)),
          application_restart_synchronization(application_durability_fact(
              application_durability_domain::rejected_object_store,
              application_durability_status::confirmed)),
          application_restart_synchronization(application_durability_fact(
              application_durability_domain::completed_evidence,
              application_durability_status::confirmed)),
      },
      durability(),
      {application_identity<application_backend_evidence_identity>(seed + 8)},
      completed);
}

} // namespace pkgapply::test::checkpoint_fixture
