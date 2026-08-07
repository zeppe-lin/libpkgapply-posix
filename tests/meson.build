# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later

if get_option('tests').allowed()
  sh = find_program('sh')
  nm = find_program('nm')

  fixture_test_deps = [
    libpkgapply_posix_dep,
    dependency('libpkgbuild-image', version: ['>=1.0.0', '<2.0.0'], required: true, static: want_static),
    dependency('libpkgbuild-plan', version: ['>=1.0.0', '<2.0.0'], required: true, static: want_static),
    dependency('libpkgcatalog', version: ['>=3.0.0', '<4.0.0'], required: true, static: want_static),
    dependency('libpkgresolve', version: ['>=2.0.0', '<3.0.0'], required: true, static: want_static),
    dependency('libpkgstate', version: ['>=3.0.0', '<4.0.0'], required: true, static: want_static),
  ]
  crypto_test_deps = [libpkgapply_posix_dep, libcrypto_dep]
  fixture_crypto_test_deps = fixture_test_deps + [libcrypto_dep]

  # White-box mechanism tests include non-installed headers from src/.  They
  # must exercise the private implementation without promoting detail symbols
  # into the installed shared ABI.
  libpkgapply_posix_internal_test_library = static_library(
    'pkgapply-posix-test-implementation',
    libpkgapply_posix_sources,
    include_directories: [public_inc, private_inc],
    cpp_args: visibility_cpp_args + ['-DPKGAPPLY_POSIX_BUILDING_LIBRARY'],
    dependencies: libpkgapply_posix_implementation_deps,
    install: false,
  )
  libpkgapply_posix_internal_test_dep = declare_dependency(
    link_with: libpkgapply_posix_internal_test_library,
    include_directories: [public_inc, private_inc],
    dependencies: libpkgapply_posix_implementation_deps,
  )
  internal_crypto_test_deps = [
    libpkgapply_posix_internal_test_dep,
    libcrypto_dep,
  ]

  version_header_test = executable(
    'version-header-test',
    'version_header_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('compile POSIX version header independently', version_header_test)


  posix_active_incoming_test = executable(
    'posix-active-incoming-test',
    'posix_active_incoming_test.cpp',
    dependencies: internal_crypto_test_deps,
  )
  test('posix-active-incoming-test', posix_active_incoming_test)

  posix_active_recovery_test = executable(
    'posix-active-recovery-test',
    'posix_active_recovery_test.cpp',
    dependencies: internal_crypto_test_deps,
  )
  test('posix-active-recovery-test', posix_active_recovery_test)

  posix_active_removal_test = executable(
    'posix-active-removal-test',
    'posix_active_removal_test.cpp',
    dependencies: libpkgapply_posix_internal_test_dep,
  )
  test('posix-active-removal-test', posix_active_removal_test)

  posix_active_workspace_test = executable(
    'posix-active-workspace-test',
    'posix_active_workspace_test.cpp',
    dependencies: libpkgapply_posix_internal_test_dep,
  )
  test('posix-active-workspace-test', posix_active_workspace_test)

  posix_backend_header_test = executable(
    'posix-backend-header-test',
    'posix_backend_header_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-backend-header-test', posix_backend_header_test)

  posix_backend_routes_test = executable(
    'posix-backend-routes-test',
    'posix_backend_routes_test.cpp',
    dependencies: fixture_crypto_test_deps,
  )
  test('posix-backend-routes-test', posix_backend_routes_test)

  posix_backend_test = executable(
    'posix-backend-test',
    'posix_backend_test.cpp',
    dependencies: fixture_test_deps,
  )
  test('posix-backend-test', posix_backend_test)

  posix_capture_store_header_test = executable(
    'posix-capture-store-header-test',
    'posix_capture_store_header_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-capture-store-header-test', posix_capture_store_header_test)

  posix_capture_store_test = executable(
    'posix-capture-store-test',
    'posix_capture_store_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-capture-store-test', posix_capture_store_test)

  posix_checkpoint_store_header_test = executable(
    'posix-checkpoint-store-header-test',
    'posix_checkpoint_store_header_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-checkpoint-store-header-test', posix_checkpoint_store_header_test)

  posix_checkpoint_store_test = executable(
    'posix-checkpoint-store-test',
    'posix_checkpoint_store_test.cpp',
    dependencies: fixture_test_deps,
  )
  test('posix-checkpoint-store-test', posix_checkpoint_store_test)

  posix_completed_evidence_store_header_test = executable(
    'posix-completed-evidence-store-header-test',
    'posix_completed_evidence_store_header_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-completed-evidence-store-header-test', posix_completed_evidence_store_header_test)

  posix_completed_evidence_store_test = executable(
    'posix-completed-evidence-store-test',
    'posix_completed_evidence_store_test.cpp',
    dependencies: fixture_test_deps,
  )
  test('posix-completed-evidence-store-test', posix_completed_evidence_store_test)

  posix_journal_store_header_test = executable(
    'posix-journal-store-header-test',
    'posix_journal_store_header_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-journal-store-header-test', posix_journal_store_header_test)

  posix_journal_store_test = executable(
    'posix-journal-store-test',
    'posix_journal_store_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-journal-store-test', posix_journal_store_test)

  posix_mutation_lease_header_test = executable(
    'posix-mutation-lease-header-test',
    'posix_mutation_lease_header_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-mutation-lease-header-test', posix_mutation_lease_header_test)

  posix_mutation_lease_test = executable(
    'posix-mutation-lease-test',
    'posix_mutation_lease_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-mutation-lease-test', posix_mutation_lease_test)

  posix_payload_stage_header_test = executable(
    'posix-payload-stage-header-test',
    'posix_payload_stage_header_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-payload-stage-header-test', posix_payload_stage_header_test)

  posix_payload_stage_test = executable(
    'posix-payload-stage-test',
    'posix_payload_stage_test.cpp',
    dependencies: crypto_test_deps,
  )
  test('posix-payload-stage-test', posix_payload_stage_test)

  posix_public_header_test = executable(
    'posix-public-header-test',
    'posix_public_header_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-public-header-test', posix_public_header_test)

  posix_rtti_link_test = executable(
    'posix-rtti-link-test',
    'posix_rtti_link_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-rtti-link-test', posix_rtti_link_test)

  posix_rejected_store_header_test = executable(
    'posix-rejected-store-header-test',
    'posix_rejected_store_header_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-rejected-store-header-test', posix_rejected_store_header_test)

  posix_rejected_store_test = executable(
    'posix-rejected-store-test',
    'posix_rejected_store_test.cpp',
    dependencies: fixture_crypto_test_deps,
  )
  test('posix-rejected-store-test', posix_rejected_store_test)

  posix_target_observer_header_test = executable(
    'posix-target-observer-header-test',
    'posix_target_observer_header_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-target-observer-header-test', posix_target_observer_header_test)

  posix_target_observer_test = executable(
    'posix-target-observer-test',
    'posix_target_observer_test.cpp',
    dependencies: libpkgapply_posix_dep,
  )
  test('posix-target-observer-test', posix_target_observer_test)


  if library_kind == 'shared'
    test(
      'verify reviewed POSIX ABI surface',
      sh,
      args: [
        join_paths(meson.current_source_dir(), 'check_abi_surface.sh'),
        nm.full_path(),
        libpkgapply_posix.full_path(),
        join_paths(meson.project_source_root(), 'abi/libpkgapply-posix.exports'),
      ],
    )
  endif

  test(
    'verify pkg-config metadata',
    sh,
    args: [
      join_paths(meson.current_source_dir(), 'pkgconfig_metadata_test.sh'),
      meson.project_build_root(),
    ],
  )

  test(
    'verify POSIX mutation lease source contract',
    sh,
    args: [
      join_paths(meson.current_source_dir(), 'posix_mutation_lease_source_test.sh'),
      meson.project_source_root(),
    ],
  )
  test(
    'contract architecture-contract',
    sh,
    args: [join_paths(meson.current_source_dir(), 'contracts/check_architecture_contract.sh'), meson.project_source_root()],
  )
  test(
    'contract abi-contract',
    sh,
    args: [join_paths(meson.current_source_dir(), 'contracts/check_abi_contract.sh'), meson.project_source_root()],
  )
  test(
    'contract ci-contract',
    sh,
    args: [join_paths(meson.current_source_dir(), 'contracts/check_ci_contract.sh'), meson.project_source_root()],
  )
  libpkgapply_public_include = libpkgapply_dep.get_variable(
    pkgconfig: 'includedir',
  )
  libpkgimage_public_include = libpkgimage_dep.get_variable(
    pkgconfig: 'includedir',
  )
  libpkgplan_public_include = libpkgplan_dep.get_variable(
    pkgconfig: 'includedir',
  )
  test(
    'contract documentation-contract',
    sh,
    args: [
      join_paths(meson.current_source_dir(), 'contracts/check_documentation_contract.sh'),
      meson.project_source_root(),
      libpkgapply_public_include,
      libpkgimage_public_include,
      libpkgplan_public_include,
    ],
  )
  test(
    'contract extraction-contract',
    sh,
    args: [join_paths(meson.current_source_dir(), 'contracts/check_extraction_contract.sh'), meson.project_source_root()],
  )
  test(
    'contract release-contract',
    sh,
    args: [join_paths(meson.current_source_dir(), 'contracts/check_release_contract.sh'), meson.project_source_root()],
  )
  test(
    'contract repository-contract',
    sh,
    args: [join_paths(meson.current_source_dir(), 'contracts/check_repository_contract.sh'), meson.project_source_root()],
  )
  test(
    'contract style-contract',
    sh,
    args: [
      join_paths(meson.current_source_dir(), 'contracts/check_style_contract.sh'),
      meson.project_source_root(),
      meson.project_build_root(),
    ],
  )
  test(
    'contract test-topology-contract',
    sh,
    args: [
      join_paths(meson.current_source_dir(), 'contracts/check_test_topology_contract.sh'),
      meson.project_source_root(),
    ],
  )

endif
