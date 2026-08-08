// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/backend.h>
#include <libpkgapply-posix/capture_store.h>
#include <libpkgapply-posix/checkpoint_store.h>
#include <libpkgapply-posix/completed_evidence_store.h>
#include <libpkgapply-posix/journal_store.h>
#include <libpkgapply-posix/mutation_lease.h>
#include <libpkgapply-posix/payload_stage.h>
#include <libpkgapply-posix/rejected_store.h>
#include <libpkgapply-posix/target_observer.h>

#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

void require(bool condition, std::string_view message)
{
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

} // namespace

int main()
{
  using namespace pkgapply::posix;

  const posix_backend_error backend(
      posix_backend_error_code::descriptor_invalid, EBADF, "backend");
  require(backend.code() == posix_backend_error_code::descriptor_invalid &&
              backend.system_error() == EBADF,
          "backend error lost its typed evidence");

  const capture_store_error capture(
      capture_store_error_code::source_changed, ESTALE, "path", "capture");
  require(capture.code() == capture_store_error_code::source_changed &&
              capture.system_error() == ESTALE && capture.path() == "path",
          "capture error lost its typed evidence");

  const checkpoint_store_error checkpoint(
      checkpoint_store_error_code::directory_sync_failed, EIO,
      "checkpoint", true);
  require(checkpoint.code() ==
              checkpoint_store_error_code::directory_sync_failed &&
              checkpoint.system_error() == EIO &&
              checkpoint.publication_visible(),
          "checkpoint error lost publication visibility");

  const completed_evidence_store_error completed(
      completed_evidence_store_error_code::namespace_sync_failed, EIO,
      "completed", true);
  require(completed.code() ==
              completed_evidence_store_error_code::namespace_sync_failed &&
              completed.system_error() == EIO &&
              completed.publication_visible(),
          "completed-evidence error lost publication visibility");

  const journal_store_error journal(
      journal_store_error_code::directory_sync_failed, EIO, "journal", true);
  require(journal.code() == journal_store_error_code::directory_sync_failed &&
              journal.system_error() == EIO && journal.replacement_visible(),
          "journal error lost replacement visibility");

  const target_mutation_lease_error lease(
      target_mutation_lease_error_code::lock_busy, EWOULDBLOCK, "lease");
  require(lease.code() == target_mutation_lease_error_code::lock_busy &&
              lease.system_error() == EWOULDBLOCK,
          "mutation-lease error lost its typed evidence");

  const payload_stage_error payload(
      payload_stage_error_code::stage_sync_failed, EIO, "payload");
  require(payload.code() == payload_stage_error_code::stage_sync_failed &&
              payload.system_error() == EIO,
          "payload-stage error lost its typed evidence");

  const rejected_store_error rejected(
      rejected_store_error_code::binding_mismatch, EINVAL, "path", "rejected");
  require(rejected.code() == rejected_store_error_code::binding_mismatch &&
              rejected.system_error() == EINVAL && rejected.path() == "path",
          "rejected-store error lost its typed evidence");

  const target_observer_error observer(
      target_observer_error_code::object_stat_failed, EIO, "path", "observer");
  require(observer.code() == target_observer_error_code::object_stat_failed &&
              observer.system_error() == EIO && observer.path() == "path",
          "target-observer error lost its typed evidence");

  return 0;
}
