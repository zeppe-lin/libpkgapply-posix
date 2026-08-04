# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later

man_pages = get_option('man_pages')
if not man_pages.disabled()
  scdoc = find_program('scdoc', required: man_pages.enabled())
  if scdoc.found()
    custom_target(
      'libpkgapply-posix.3',
      input: 'libpkgapply-posix.3.scdoc',
      output: 'libpkgapply-posix.3',
      command: [scdoc],
      feed: true,
      capture: true,
      build_by_default: true,
      install: true,
      install_dir: get_option('mandir') / 'man3',
      install_tag: 'man',
    )
  endif
endif
