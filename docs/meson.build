# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later

documentation_dir = get_option('datadir') / 'doc' / meson.project_name()

install_data(
  '../CONTRIBUTING.md',
  '../DESIGN.md',
  '../HISTORY.md',
  '../MAINTAINING.md',
  '../README.md',
  '../TESTING.md',
  '../COPYING',
  '../COPYRIGHT',
  install_dir: documentation_dir,
  install_tag: 'doc',
)

install_data(
  'abi.md',
  'code-style.md',
  'html.md',
  'integration.md',
  'manpage-markdown.md',
  'mechanisms.md',
  'qualification.md',
  install_dir: documentation_dir,
  install_tag: 'doc',
)

install_data(
  'history/libpkgapply-2.3-extraction.md',
  'history/libpkgapply-2.3-extraction.sha256',
  install_dir: documentation_dir / 'history',
  install_tag: 'doc',
)

install_data(
  'man/libpkgapply-posix.3.md',
  install_dir: documentation_dir / 'man',
  install_tag: 'doc',
)

subdir('man')

install_data(
  'assets/house.css',
  'assets/doxygen-extra.css',
  install_dir: documentation_dir / 'assets',
  install_tag: 'doc',
)

html_docs_enabled = get_option('html_docs').enabled()
html_docs_target = []
html_docs_output_dir = ''

if html_docs_enabled
  pandoc = find_program('pandoc', required: true)
  doxygen = find_program('doxygen', required: true)
  html_docs_builder = find_program(meson.project_source_root() / 'tools/build-html-docs.py')
  html_docs_checker = find_program(meson.project_source_root() / 'tools/check-html-docs.py')
  html_docs_installer = find_program(meson.project_source_root() / 'tools/install-html-docs.py')

  html_docs_output_dir = (
    meson.current_build_dir()
    / 'html'
    / meson.project_name()
    / meson.project_version()
  )
  html_docs_sources = files(
    '../CONTRIBUTING.md',
    '../DESIGN.md',
    '../HISTORY.md',
    '../MAINTAINING.md',
    '../README.md',
    '../TESTING.md',
    'abi.md',
    'code-style.md',
    'html.md',
    'integration.md',
    'manpage-markdown.md',
    'mechanisms.md',
    'qualification.md',
    'history/libpkgapply-2.3-extraction.md',
    'history/libpkgapply-2.3-extraction.sha256',
    'man/libpkgapply-posix.3.md',
    'assets/house.css',
    'assets/doxygen-extra.css',
    'html-manifest.json',
    '../COPYING',
    '../COPYRIGHT',
    '../Doxyfile',
    '../tools/build-html-docs.py',
    '../tools/check-html-docs.py',
    '../tools/install-html-docs.py',
    '../tools/update-man-pages.sh',
    '../tools/canonicalize-man-roff.awk',
    '../include/libpkgapply-posix/backend.h',
    '../include/libpkgapply-posix/capture_store.h',
    '../include/libpkgapply-posix/checkpoint_store.h',
    '../include/libpkgapply-posix/completed_evidence_store.h',
    '../include/libpkgapply-posix/export.h',
    '../include/libpkgapply-posix/journal_store.h',
    '../include/libpkgapply-posix/libpkgapply-posix.h',
    '../include/libpkgapply-posix/mutation_lease.h',
    '../include/libpkgapply-posix/payload_stage.h',
    '../include/libpkgapply-posix/rejected_store.h',
    '../include/libpkgapply-posix/target_observer.h',
    '../include/libpkgapply-posix/version.h',
  )

  html_docs_target = custom_target(
    'html-docs',
    input: html_docs_sources,
    output: 'html-docs.stamp',
    command: [
      html_docs_builder,
      '--source-root', meson.project_source_root(),
      '--manifest', meson.current_source_dir() / 'html-manifest.json',
      '--output-dir', html_docs_output_dir,
      '--project-version', meson.project_version(),
      '--pandoc', pandoc.full_path(),
      '--doxygen', doxygen.full_path(),
      '--checker', html_docs_checker.full_path(),
      '--stamp', '@OUTPUT@',
    ],
    build_by_default: true,
  )

  meson.add_install_script(
    html_docs_installer,
    html_docs_target,
    html_docs_output_dir,
    (
      get_option('datadir')
      / 'htmldocs'
      / meson.project_name()
      / meson.project_version()
    ),
    install_tag: 'html-docs',
  )
endif
