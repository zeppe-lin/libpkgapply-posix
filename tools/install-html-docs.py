#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"install-html-docs: {message}")


def main() -> int:
    if len(sys.argv) != 4:
        fail("usage: install-html-docs.py STAMP SOURCE-DIR INSTALL-SUBDIR")
    stamp = Path(sys.argv[1])
    source = Path(sys.argv[2])
    relative = Path(sys.argv[3])
    if relative.is_absolute() or ".." in relative.parts:
        fail(f"install subdirectory is not relative and contained: {relative}")
    if not stamp.is_file():
        fail(f"HTML documentation stamp is missing: {stamp}")
    if not (source / "index.html").is_file():
        fail(f"HTML documentation source is incomplete: {source}")
    prefix_value = os.environ.get("MESON_INSTALL_DESTDIR_PREFIX")
    if not prefix_value:
        fail("MESON_INSTALL_DESTDIR_PREFIX is not set")
    destination = Path(prefix_value) / relative
    if os.environ.get("MESON_INSTALL_DRY_RUN") == "1":
        print(f"Would install HTML documentation to {destination}")
        return 0
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, copy_function=shutil.copy2)
    if os.environ.get("MESON_INSTALL_QUIET") != "1":
        print(f"Installing HTML documentation to {destination}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
