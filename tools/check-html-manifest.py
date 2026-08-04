#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"html-manifest-contract: {message}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--project", required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    manifest_path = root / "docs/html-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read manifest: {error}")
    if manifest.get("project") != args.project:
        fail("manifest project does not match the repository product")
    documents = manifest.get("documents")
    if not isinstance(documents, list) or not documents:
        fail("document inventory is empty")

    sources: list[str] = []
    outputs: list[str] = []
    for item in documents:
        if not isinstance(item, dict):
            fail("document entry is not an object")
        source = item.get("source")
        output = item.get("output")
        title = item.get("title")
        if not all(isinstance(value, str) and value for value in (source, output, title)):
            fail("document entry is incomplete")
        source_path = Path(source)
        output_path = Path(output)
        if source_path.is_absolute() or ".." in source_path.parts or source_path.suffix != ".md":
            fail(f"unsafe source path: {source}")
        if output_path.is_absolute() or ".." in output_path.parts or output_path.suffix != ".html":
            fail(f"unsafe output path: {output}")
        if not (root / source_path).is_file():
            fail(f"manifest source is missing: {source}")
        sources.append(source)
        outputs.append(output)

    if len(sources) != len(set(sources)):
        fail("manifest repeats a Markdown source")
    if len(outputs) != len(set(outputs)):
        fail("manifest repeats an HTML output")
    if not any(source == "README.md" and output == "index.html" for source, output in zip(sources, outputs)):
        fail("README.md is not bound to index.html")

    authoritative = {
        path.relative_to(root).as_posix()
        for path in root.glob("*.md")
    }
    authoritative.update(
        path.relative_to(root).as_posix()
        for path in (root / "docs").rglob("*.md")
    )
    if set(sources) != authoritative:
        fail(
            "manifest does not exactly cover authoritative Markdown; "
            f"missing={sorted(authoritative - set(sources))}; "
            f"extra={sorted(set(sources) - authoritative)}"
        )

    for required in (
        "docs/assets/house.css",
        "docs/assets/doxygen-extra.css",
        "docs/html.md",
        "docs/manpage-markdown.md",
        "tools/build-html-docs.py",
        "tools/check-html-docs.py",
        "tools/install-html-docs.py",
        "tools/render-man-markdown.py",
        "tools/check-man-markdown.py",
    ):
        if not (root / required).is_file():
            fail(f"HTML documentation input is missing: {required}")

    options = root / ("meson.options" if (root / "meson.options").exists() else "meson_options.txt")
    if not re.search(r"['\"]html_docs['\"]", options.read_text(encoding="utf-8")):
        fail("Meson html_docs feature is absent")

    print("html-manifest-contract: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
