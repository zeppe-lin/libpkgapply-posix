#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"render-man-markdown: {message}")


def render(source: Path, project: str, version: str) -> str:
    lines = source.read_text(encoding="utf-8").splitlines()
    if not lines or not re.fullmatch(r"[A-Z0-9_.+-]+\([1-9]\)", lines[0]):
        fail(f"invalid scdoc title in {source}")

    output = [
        f"% {lines[0]} {project} | Version {version}",
        "",
        f"<!-- Generated from {source.name}; do not edit. -->",
        "",
    ]
    in_code = False
    for raw in lines[1:]:
        line = raw[1:] if raw.startswith("\t") else raw
        if line.strip() == "```":
            in_code = not in_code
            output.append(line)
            continue
        if not in_code:
            # scdoc bold uses single asterisks. Markdown reserves the same
            # spelling for emphasis, so promote exact scdoc spans to strong.
            line = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"**\1**", line)
        output.append(line.rstrip())

    while output and output[-1] == "":
        output.pop()
    return "\n".join(output) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        render(args.source, args.project, args.version),
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
