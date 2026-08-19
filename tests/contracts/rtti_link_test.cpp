// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/libpkgapply-posix.h>

#include <array>
#include <typeinfo>

int main()
{
  using namespace pkgapply::posix;

  const std::array<const std::type_info*, 12> public_rtti{
      &typeid(application_journal_store),
      &typeid(application_payload_stage),
      &typeid(application_posix_backend),
      &typeid(capture_store_error),
      &typeid(completed_evidence_store_error),
      &typeid(journal_store_error),
      &typeid(payload_stage_error),
      &typeid(posix_backend_error),
      &typeid(rejected_store_error),
      &typeid(target_mutation_lease),
      &typeid(target_mutation_lease_error),
      &typeid(target_observer_error),
  };

  for (const auto* const info : public_rtti) {
    if (info == nullptr || info->name() == nullptr || info->name()[0] == '\0') {
      return 1;
    }
  }

  return 0;
}
