#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

sys.dont_write_bytecode = True


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"man-markdown-contract: {message}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    renderer_path = root / "tools/render-man-markdown.py"
    spec = importlib.util.spec_from_file_location("render_man_markdown", renderer_path)
    if spec is None or spec.loader is None:
        fail("cannot load manual Markdown renderer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    sources = sorted((root / "man").glob("*.scdoc"))
    if not sources:
        fail("no canonical scdoc manuals found")
    expected_names = {source.with_suffix(".md").name for source in sources}
    actual_names = {path.name for path in (root / "docs/man").glob("*.md")}
    if actual_names != expected_names:
        fail(
            "derived manual inventory mismatch; "
            f"missing={sorted(expected_names - actual_names)}; "
            f"extra={sorted(actual_names - expected_names)}"
        )

    for source in sources:
        derived = root / "docs/man" / source.with_suffix(".md").name
        expected = module.render(source, args.project, args.version)
        actual = derived.read_text(encoding="utf-8")
        if actual != expected:
            fail(f"stale derived manual: {derived.relative_to(root)}")

    print("man-markdown-contract: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
