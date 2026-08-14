# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later

if get_option('tests').allowed()
  sh = find_program('sh')
  nm = find_program('nm')
  test_inc = include_directories('.', 'fixtures')

  libpkgbuild_image_test_dep = dependency(
    'libpkgbuild-image', version: ['>=1.0.0', '<2.0.0'], required: true,
    static: want_static,
  )
  libpkgbuild_plan_test_dep = dependency(
    'libpkgbuild-plan', version: ['>=1.0.0', '<2.0.0'], required: true,
    static: want_static,
  )
  libpkgbuild_test_dep = dependency(
    'libpkgbuild', version: ['>=3.0.0', '<4.0.0'], required: true,
    static: want_static,
  )
  libpkgcatalog_test_dep = dependency(
    'libpkgcatalog', version: ['>=3.0.0', '<4.0.0'], required: true,
    static: want_static,
  )
  libpkgresolve_test_dep = dependency(
    'libpkgresolve', version: ['>=3.0.0', '<4.0.0'], required: true,
    static: want_static,
  )
  libpkgsource_plan_test_dep = dependency(
    'libpkgsource-plan', version: ['>=1.0.0', '<2.0.0'], required: true,
    static: want_static,
  )
  libpkgsource_test_dep = dependency(
    'libpkgsource', version: ['>=4.0.0', '<5.0.0'], required: true,
    static: want_static,
  )
  libpkgstate_test_dep = dependency(
    'libpkgstate', version: ['>=3.0.0', '<4.0.0'], required: true,
    static: want_static,
  )

  fixture_test_deps = [
    libpkgapply_posix_dep,
    libpkgbuild_image_test_dep,
    libpkgbuild_plan_test_dep,
    libpkgcatalog_test_dep,
    libpkgresolve_test_dep,
    libpkgstate_test_dep,
  ]
  crypto_test_deps = [libpkgapply_posix_dep, libcrypto_dep]
  fixture_crypto_test_deps = fixture_test_deps + [libcrypto_dep]

  # White-box mechanism tests include non-installed headers from src/. They
  # exercise the private implementation without promoting detail symbols into
  # the installed shared ABI.
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

  error_value_test = executable(
    'error-value-test',
    'unit/error_value_test.cpp',
    dependencies: libpkgapply_posix_dep,
    install: false,
  )
  test('error-value', error_value_test, suite: 'unit')

  foreach spec : [
    ['active-incoming', 'mechanism/posix_active_incoming_test.cpp', internal_crypto_test_deps],
    ['active-recovery', 'mechanism/posix_active_recovery_test.cpp', internal_crypto_test_deps],
    ['active-removal', 'mechanism/posix_active_removal_test.cpp', [libpkgapply_posix_internal_test_dep]],
    ['active-workspace', 'mechanism/posix_active_workspace_test.cpp', [libpkgapply_posix_internal_test_dep]],
    ['capture-store', 'mechanism/posix_capture_store_test.cpp', crypto_test_deps],
    ['checkpoint-store', 'mechanism/posix_checkpoint_store_test.cpp', fixture_test_deps],
    ['completed-evidence-store', 'mechanism/posix_completed_evidence_store_test.cpp', fixture_test_deps],
    ['journal-store', 'mechanism/posix_journal_store_test.cpp', [libpkgapply_posix_dep]],
    ['mutation-lease', 'mechanism/posix_mutation_lease_test.cpp', [libpkgapply_posix_dep]],
    ['payload-stage', 'mechanism/posix_payload_stage_test.cpp', crypto_test_deps],
    ['rejected-store', 'mechanism/posix_rejected_store_test.cpp', fixture_crypto_test_deps],
    ['target-observer', 'mechanism/posix_target_observer_test.cpp', [libpkgapply_posix_dep]],
  ]
    target = executable(
      spec[0] + '-test',
      spec[1],
      include_directories: test_inc,
      dependencies: spec[2],
      install: false,
    )
    test(spec[0], target, suite: 'mechanism')
  endforeach

  foreach spec : [
    ['backend', 'integration/posix_backend_test.cpp', fixture_test_deps],
    ['backend-routes', 'integration/posix_backend_routes_test.cpp', fixture_crypto_test_deps],
    ['durability-failure', 'integration/durability_failure_test.cpp', fixture_test_deps],
  ]
    target = executable(
      spec[0] + '-test',
      spec[1],
      include_directories: test_inc,
      dependencies: spec[2],
      install: false,
    )
    test(spec[0], target, suite: 'integration')
  endforeach

  public_headers = [
    'backend.h',
    'capture_store.h',
    'checkpoint_store.h',
    'completed_evidence_store.h',
    'export.h',
    'journal_store.h',
    'libpkgapply-posix.h',
    'mutation_lease.h',
    'payload_stage.h',
    'rejected_store.h',
    'target_observer.h',
    'version.h',
  ]
  foreach header : public_headers
    target = executable(
      'header-' + header.underscorify(),
      'header/public_header_compile.cpp',
      cpp_args: [
        '-DPKGAPPLY_POSIX_TEST_HEADER="libpkgapply-posix/' + header + '"',
      ],
      dependencies: libpkgapply_posix_dep,
      install: false,
    )
    test('header-' + header.underscorify(), target, suite: 'header')
  endforeach

  rtti_link_test = executable(
    'rtti-link-test',
    'contracts/rtti_link_test.cpp',
    dependencies: libpkgapply_posix_dep,
    install: false,
  )
  test('rtti-link', rtti_link_test, suite: 'contract')

  if library_kind == 'shared'
    test(
      'abi-surface',
      sh,
      args: [
        meson.current_source_dir() / 'contracts/check_abi_surface.sh',
        nm.full_path(),
        libpkgapply_posix.full_path(),
        meson.project_source_root() / 'abi/libpkgapply-posix.exports',
      ],
      suite: 'contract',
    )
  endif

  test(
    'pkgconfig-metadata',
    sh,
    args: [
      meson.current_source_dir() / 'contracts/check_pkgconfig_metadata.sh',
      meson.project_build_root(),
    ],
    suite: 'contract',
  )
  test(
    'mutation-lease-source',
    sh,
    args: [
      meson.current_source_dir() / 'contracts/check_mutation_lease_source.sh',
      meson.project_source_root(),
    ],
    suite: 'contract',
  )

  foreach contract : [
    'architecture_contract',
    'abi_contract',
    'ci_contract',
    'documentation_source_contract',
    'extraction_contract',
    'manpage_normalizer',
    'manpage_source',
    'release_contract',
    'regular_record_refusal_contract',
    'repository_contract',
    'test_topology_contract',
  ]
    test(
      contract.replace('_', '-'),
      sh,
      args: [
        meson.current_source_dir() / ('contracts/check_' + contract + '.sh'),
        meson.project_source_root(),
      ],
      suite: 'contract',
    )
  endforeach

  pandoc_for_tests = find_program('pandoc', required: false)
  if pandoc_for_tests.found()
    test(
      'generated-manpages',
      sh,
      args: [
        meson.current_source_dir() / 'contracts/check_manpage_generated.sh',
        meson.project_source_root(),
        pandoc_for_tests.full_path(),
      ],
      suite: 'contract',
    )
  endif

  # The Doxygen parser compiles installed public headers in isolation. Pass the
  # complete transitive public include closure explicitly so qualification
  # cannot borrow zoo headers from one ambient installation prefix.
  libpkgapply_public_include = libpkgapply_dep.get_variable(pkgconfig: 'includedir')
  libpkgbuild_plan_public_include = libpkgbuild_plan_test_dep.get_variable(pkgconfig: 'includedir')
  libpkgplan_public_include = libpkgplan_dep.get_variable(pkgconfig: 'includedir')
  libpkgbuild_image_public_include = libpkgbuild_image_test_dep.get_variable(pkgconfig: 'includedir')
  libpkgbuild_public_include = libpkgbuild_test_dep.get_variable(pkgconfig: 'includedir')
  libpkgimage_public_include = libpkgimage_dep.get_variable(pkgconfig: 'includedir')
  libpkgsource_plan_public_include = libpkgsource_plan_test_dep.get_variable(pkgconfig: 'includedir')
  libpkgsource_public_include = libpkgsource_test_dep.get_variable(pkgconfig: 'includedir')
  libpkgresolve_public_include = libpkgresolve_test_dep.get_variable(pkgconfig: 'includedir')
  libpkgcatalog_public_include = libpkgcatalog_test_dep.get_variable(pkgconfig: 'includedir')
  libpkgstate_public_include = libpkgstate_test_dep.get_variable(pkgconfig: 'includedir')
  test(
    'documentation-contract',
    sh,
    args: [
      meson.current_source_dir() / 'contracts/check_documentation_contract.sh',
      meson.project_source_root(),
      libpkgapply_public_include,
      libpkgbuild_plan_public_include,
      libpkgplan_public_include,
      libpkgbuild_image_public_include,
      libpkgbuild_public_include,
      libpkgimage_public_include,
      libpkgsource_plan_public_include,
      libpkgsource_public_include,
      libpkgresolve_public_include,
      libpkgcatalog_public_include,
      libpkgstate_public_include,
    ],
    suite: 'contract',
  )

  test(
    'style-contract',
    sh,
    args: [
      meson.current_source_dir() / 'contracts/check_style_contract.sh',
      meson.project_source_root(),
      meson.project_build_root(),
    ],
    suite: 'contract',
  )
endif
