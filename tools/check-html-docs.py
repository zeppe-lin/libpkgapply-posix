#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import json
import os
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attribute = "href" if tag in {"a", "link"} else "src" if tag in {"img", "script"} else None
        if attribute is None:
            return
        for name, value in attrs:
            if name == attribute and value:
                self.links.append(value)


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"html-docs-test: {message}")


def local_target(page: Path, link: str) -> Path | None:
    parts = urlsplit(link)
    if parts.scheme or parts.netloc or link.startswith("#"):
        return None
    path = unquote(parts.path)
    if not path:
        return None
    if path.startswith("/"):
        fail(f"absolute local link in {page}: {link}")
    if path.endswith(".md"):
        fail(f"source documentation link escaped into {page}: {link}")
    return (page.parent / path).resolve()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--forbid-path", action="append", default=[])
    args = parser.parse_args()

    root = args.root.resolve()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        outputs = [item["output"] for item in manifest["documents"]]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        fail(f"invalid manifest: {error}")
    required = outputs + [
        "api/index.html",
        "assets/house.css",
        "assets/doxygen-extra.css",
        "legal/COPYING",
        "legal/COPYRIGHT",
    ]
    for relative in required:
        path = root / relative
        if not path.is_file() or path.stat().st_size == 0:
            fail(f"missing generated artifact: {relative}")

    pages = sorted(root.rglob("*.html"))
    if not pages:
        fail("generated tree contains no HTML pages")
    forbidden = [os.fsencode(value) for value in args.forbid_path if value]
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        data = path.read_bytes()
        for value in forbidden:
            if value in data:
                fail(f"absolute build or source path escaped into {path.relative_to(root)}")
    for page in pages:
        parser_instance = LinkParser()
        parser_instance.feed(page.read_text(encoding="utf-8"))
        for link in parser_instance.links:
            target = local_target(page, link)
            if target is None:
                continue
            try:
                target.relative_to(root)
            except ValueError:
                fail(f"local link escapes documentation root in {page.relative_to(root)}: {link}")
            if not target.exists():
                fail(f"broken local link in {page.relative_to(root)}: {link}")
    print("html-docs-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
