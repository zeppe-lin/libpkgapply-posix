# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later

public_inc = include_directories('../include')
private_inc = include_directories('.')

libpkgapply_posix = library(
  'pkgapply-posix',
  [
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

libpkgapply_posix_dep = declare_dependency(
  link_with: libpkgapply_posix,
  include_directories: public_inc,
  dependencies: [libpkgapply_dep, libpkgimage_dep, libpkgplan_dep],
  version: meson.project_version(),
)
meson.override_dependency('libpkgapply-posix', libpkgapply_posix_dep)

install_headers(
  '../include/libpkgapply-posix/backend.h',
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
  requires: [libpkgapply_dep, libpkgimage_dep, libpkgplan_dep],
  requires_private: [libcrypto_dep],
)
