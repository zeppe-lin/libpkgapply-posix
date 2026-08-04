# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later

public_inc = include_directories('../include')
private_inc = include_directories('.')

elf_export_script_path = meson.project_source_root() / 'abi/libpkgapply-posix.exports'

libpkgapply_posix = library(
  'pkgapply-posix',
  [
    'version.cpp',
    'backend.cpp',
    'active_namespace.cpp',
    'active_workspace.cpp',
    'capture_store.cpp',
    'completed_evidence_store.cpp',
    'checkpoint_store.cpp',
    'journal_store.cpp',
    'mutation_lease.cpp',
    'payload_stage.cpp',
    'rejected_store.cpp',
    'target_observer.cpp',
  ],
  include_directories: [public_inc, private_inc],
  cpp_args: visibility_cpp_args + ['-DPKGAPPLY_POSIX_BUILDING_LIBRARY'],
  gnu_symbol_visibility: 'hidden',
  link_args: ['-Wl,--version-script=' + elf_export_script_path],
  link_depends: files('../abi/libpkgapply-posix.exports'),
  dependencies: [
    libpkgapply_dep,
    libpkgimage_dep,
    libpkgplan_dep,
    libcrypto_dep,
  ],
  install: true,
  version: meson.project_version(),
  soversion: '2',
)

libpkgapply_posix_consumer_deps = [libpkgapply_dep, libpkgimage_dep]
if want_static
  libpkgapply_posix_consumer_deps += [libpkgplan_dep, libcrypto_dep]
endif

libpkgapply_posix_dep = declare_dependency(
  link_with: libpkgapply_posix,
  include_directories: public_inc,
  dependencies: libpkgapply_posix_consumer_deps,
  version: meson.project_version(),
)
meson.override_dependency('libpkgapply-posix', libpkgapply_posix_dep)

install_headers(
  '../include/libpkgapply-posix/backend.h',
  '../include/libpkgapply-posix/export.h',
  '../include/libpkgapply-posix/version.h',
  '../include/libpkgapply-posix/libpkgapply-posix.h',
  '../include/libpkgapply-posix/capture_store.h',
  '../include/libpkgapply-posix/completed_evidence_store.h',
  '../include/libpkgapply-posix/checkpoint_store.h',
  '../include/libpkgapply-posix/journal_store.h',
  '../include/libpkgapply-posix/mutation_lease.h',
  '../include/libpkgapply-posix/payload_stage.h',
  '../include/libpkgapply-posix/rejected_store.h',
  '../include/libpkgapply-posix/target_observer.h',
  subdir: 'libpkgapply-posix',
)

pkgconf.generate(
  libpkgapply_posix,
  name: 'libpkgapply-posix',
  filebase: 'libpkgapply-posix',
  description: 'POSIX mechanisms for libpkgapply',
  subdirs: '.',
  requires: [
    'libpkgapply >= 3.0.0',
    'libpkgimage >= 0.4.0',
  ],
  requires_private: [
    'libpkgplan >= 0.3.0',
    libcrypto_dep,
  ],
)
