#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"public-documentation-contract: {message}")


def documented_before(lines: list[str], index: int) -> bool:
    cursor = index - 1
    while cursor >= 0 and not lines[cursor].strip():
        cursor -= 1
    if cursor < 0:
        return False
    previous = lines[cursor].strip()
    if previous.startswith(("///", "//!")):
        return True
    if previous.endswith("*/"):
        while cursor >= 0:
            current = lines[cursor]
            if "/**" in current or "/*!" in current:
                return True
            if "/*" in current:
                return False
            cursor -= 1
    return False


def doxygen_setting(text: str, name: str) -> str | None:
    match = re.search(rf"^{re.escape(name)}\s*=\s*(\S+)", text, re.MULTILINE)
    return match.group(1) if match else None


def check_enum_documentation(path: Path, lines: list[str], root: Path) -> None:
    inside = False
    depth = 0
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not inside and re.search(r"\benum\s+class\s+\w+", stripped):
            inside = True
            depth = line.count("{") - line.count("}")
            continue
        if not inside:
            continue
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            inside = False
            continue
        candidate = stripped.split("//", 1)[0].strip()
        if not candidate or candidate.startswith(("/*", "*", "!", "{")):
            continue
        if candidate in {"};", "}"}:
            continue
        if re.fullmatch(r"[A-Za-z_]\w*(?:\s*=\s*[^,]+)?\s*,?", candidate):
            if "///<" not in stripped and "//!<" not in stripped and not documented_before(lines, index):
                fail(
                    "undocumented enum value: "
                    f"{path.relative_to(root)}:{index + 1}"
                )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("include_subdir")
    parser.add_argument("umbrella")
    args = parser.parse_args()

    root = args.root.resolve()
    include_dir = root / "include" / args.include_subdir
    if not include_dir.is_dir():
        fail(f"missing public include directory: {include_dir.relative_to(root)}")

    headers = sorted(include_dir.glob("*.h"))
    if not headers:
        fail("no public headers discovered")

    for path in headers:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        if not re.search(r"(?:\\|@)file\b", text):
            fail(f"missing file contract: {path.relative_to(root)}")
        for index, line in enumerate(lines):
            if "= delete;" not in line:
                continue
            start = index
            balance = line.count(")") - line.count("(")
            while start > 0 and balance > 0:
                start -= 1
                balance += lines[start].count(")") - lines[start].count("(")
            if (
                start > 0
                and "operator=(" in lines[start]
                and lines[start - 1].strip().endswith("&")
            ):
                start -= 1
            if not documented_before(lines, start):
                fail(
                    "undocumented deleted operation: "
                    f"{path.relative_to(root)}:{start + 1}"
                )
        check_enum_documentation(path, lines, root)

    umbrella = include_dir / args.umbrella
    if not umbrella.is_file():
        fail(f"missing umbrella: {umbrella.relative_to(root)}")
    actual = re.findall(
        r"^#include <([^>]+)>",
        umbrella.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    expected = [
        f"{args.include_subdir}/{path.name}"
        for path in headers
        if path != umbrella
    ]
    if len(actual) != len(set(actual)):
        fail("umbrella repeats a public header")
    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        fail(f"umbrella closure mismatch; missing={missing}; extra={extra}")

    doxyfile = root / "Doxyfile"
    if not doxyfile.is_file():
        fail("missing Doxyfile")
    configuration = doxyfile.read_text(encoding="utf-8")
    for name, expected_value in (
        ("EXTRACT_PRIVATE", "NO"),
        ("WARN_IF_UNDOCUMENTED", "YES"),
        ("WARN_NO_PARAMDOC", "YES"),
    ):
        if doxygen_setting(configuration, name) != expected_value:
            fail(f"Doxyfile must set {name} = {expected_value}")
    if doxygen_setting(configuration, "WARN_AS_ERROR") not in {
        "YES",
        "FAIL_ON_WARNINGS",
    }:
        fail("Doxyfile must treat warnings as errors")

    print("public-documentation-contract: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
