#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"installed-documentation: {message}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("prefix", type=Path)
    parser.add_argument("project")
    args = parser.parse_args()

    manifest_path = Path("docs/html-manifest.json")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read source manifest: {error}")
    if manifest.get("project") != args.project:
        fail("source manifest belongs to another product")

    installed_root = args.prefix / "share/doc" / args.project
    for item in manifest["documents"]:
        source = Path(item["source"])
        relative = Path(*source.parts[1:]) if source.parts[0] == "docs" else Path(source.name)
        installed = installed_root / relative
        if not installed.is_file() or installed.stat().st_size == 0:
            fail(f"missing installed source: {relative}")

    for relative in (
        Path("COPYING"),
        Path("COPYRIGHT"),
        Path("assets/house.css"),
        Path("assets/doxygen-extra.css"),
    ):
        installed = installed_root / relative
        if not installed.is_file() or installed.stat().st_size == 0:
            fail(f"missing installed source: {relative}")

    print("installed-documentation: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
