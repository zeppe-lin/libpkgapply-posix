#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"build-html-docs: {message}")


def run(command: list[str], *, cwd: Path | None = None, stdin: str | None = None) -> None:
    completed = subprocess.run(command, cwd=cwd, input=stdin, text=True, check=False)
    if completed.returncode != 0:
        fail(f"command failed ({completed.returncode}): {' '.join(command)}")


def load_manifest(path: Path) -> tuple[str, list[tuple[str, str, str]]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read manifest {path}: {error}")
    project = value.get("project")
    documents = value.get("documents")
    if not isinstance(project, str) or not project:
        fail("manifest project is missing")
    if not isinstance(documents, list) or not documents:
        fail("manifest document inventory is empty")
    result: list[tuple[str, str, str]] = []
    sources: set[str] = set()
    outputs: set[str] = set()
    for item in documents:
        if not isinstance(item, dict):
            fail("manifest document entry is not an object")
        source = item.get("source")
        output = item.get("output")
        title = item.get("title")
        if not all(isinstance(part, str) and part for part in (source, output, title)):
            fail("manifest document entry is incomplete")
        source_path = Path(source)
        output_path = Path(output)
        if source_path.is_absolute() or ".." in source_path.parts or source_path.suffix != ".md":
            fail(f"unsafe Markdown source path: {source}")
        if output_path.is_absolute() or ".." in output_path.parts or output_path.suffix != ".html":
            fail(f"unsafe HTML output path: {output}")
        if source in sources or output in outputs:
            fail(f"duplicate manifest path: {source} -> {output}")
        sources.add(source)
        outputs.add(output)
        result.append((source, output, title))
    if "README.md" not in sources or "index.html" not in outputs:
        fail("manifest must bind README.md to the documentation home")
    return project, result


def pandoc_version(pandoc: str) -> None:
    completed = subprocess.run([pandoc, "--version"], text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        fail(f"cannot execute Pandoc: {pandoc}")
    first = completed.stdout.splitlines()[0] if completed.stdout else ""
    match = re.fullmatch(r"pandoc (\d+)\.(\d+)(?:\..*)?", first)
    if match is None:
        fail(f"cannot parse Pandoc version: {first}")
    major, minor = (int(value) for value in match.groups())
    if major != 3 or minor < 1:
        fail(f"Pandoc 3.1 through 3.x is required; found {first.removeprefix('pandoc ')}")


def pandoc_highlighting_option(pandoc: str) -> str:
    completed = subprocess.run([pandoc, "--help"], text=True, capture_output=True, check=False)
    return "--syntax-highlighting=none" if "--syntax-highlighting" in completed.stdout else "--no-highlight"


def relative_link(page: Path, target: str) -> str:
    return os.path.relpath(target, page.parent.as_posix()).replace(os.sep, "/")


def navigation(project: str, page: Path, version: str, outputs: set[str]) -> str:
    preferred = [
        ("Home", "index.html"),
        ("Architecture", "architecture.html"),
        ("Mechanisms", "mechanisms.html"),
        ("Storage", "storage.html"),
        ("Integration", "integration.html"),
        ("ABI", "abi.html"),
    ]
    manual = next((name for name in sorted(outputs) if name.startswith("manual/")), None)
    if manual is not None:
        preferred.append(("Manuals", manual))
    preferred.append(("API", "api/index.html"))
    history = "history.html" if "history.html" in outputs else "changelog.html" if "changelog.html" in outputs else None
    if history is not None:
        preferred.append(("History", history))
    links = "\n".join(
        f'<a href="{html.escape(relative_link(page, target))}">{html.escape(label)}</a>'
        for label, target in preferred
        if target in outputs or target == "api/index.html"
    )
    return (
        '<nav class="house-nav">\n'
        f'<a class="project" href="{html.escape(relative_link(page, "index.html"))}">'
        f"{html.escape(project)} {html.escape(version)}</a>\n{links}\n</nav>\n"
    )


def footer(project: str, version: str) -> str:
    return (
        '<footer class="house-footer">'
        f"Generated from {html.escape(project)} {html.escape(version)} authoritative sources."
        "</footer>\n"
    )


def render_markdown(
    pandoc: str,
    source_root: Path,
    output_root: Path,
    project: str,
    version: str,
    documents: list[tuple[str, str, str]],
) -> None:
    highlighting = pandoc_highlighting_option(pandoc)
    outputs = {output for _, output, _ in documents}
    with tempfile.TemporaryDirectory(prefix=f"{project}-html-") as temp_name:
        temp = Path(temp_name)
        for source_name, output_name, title in documents:
            source = source_root / source_name
            if not source.is_file():
                fail(f"missing Markdown source: {source_name}")
            output = output_root / output_name
            output.parent.mkdir(parents=True, exist_ok=True)
            page = Path(output_name)
            nav = temp / "nav.html"
            nav.write_text(navigation(project, page, version, outputs), encoding="utf-8", newline="\n")
            tail = temp / "footer.html"
            tail.write_text(footer(project, version), encoding="utf-8", newline="\n")
            run([
                pandoc,
                "--from=markdown-smart",
                "--to=html5",
                "--standalone",
                "--fail-if-warnings",
                "--eol=lf",
                "--wrap=none",
                highlighting,
                f"--metadata=pagetitle:{title}",
                f"--css={relative_link(page, 'assets/house.css')}",
                f"--include-before-body={nav}",
                f"--include-after-body={tail}",
                str(source),
                "--output",
                str(output),
            ])


def doxygen_setting(configuration: str, name: str) -> str | None:
    match = re.search(
        rf"^\s*{re.escape(name)}\s*=\s*(\S+)\s*$",
        configuration,
        re.MULTILINE,
    )
    return match.group(1) if match else None


def doxygen_path(path: Path) -> str:
    return '"' + str(path).replace('\\', '\\\\').replace('"', '\\"') + '"'


def compose_doxygen_configuration(
    source_root: Path, output_root: Path, version: str
) -> str:
    base = source_root / "Doxyfile"
    if not base.is_file():
        fail("missing Doxyfile")
    configuration = base.read_text(encoding="utf-8")

    inputs = [(source_root / "include").resolve()]
    mainpage_value = doxygen_setting(configuration, "USE_MDFILE_AS_MAINPAGE")
    if mainpage_value is not None:
        mainpage_relative = Path(mainpage_value)
        if mainpage_relative.is_absolute() or ".." in mainpage_relative.parts:
            fail(f"Doxygen main page is not a contained relative path: {mainpage_value}")
        mainpage = (source_root / mainpage_relative).resolve()
        try:
            mainpage.relative_to(source_root.resolve())
        except ValueError:
            fail(f"Doxygen main page escapes source root: {mainpage_value}")
        if not mainpage.is_file():
            fail(f"Doxygen main page is missing: {mainpage_value}")
        inputs.append(mainpage)

    input_value = " ".join(doxygen_path(path) for path in inputs)
    return configuration + "\n" + "\n".join([
        f"PROJECT_NUMBER = {version}",
        f"OUTPUT_DIRECTORY = {output_root}",
        f"INPUT = {input_value}",
        "FULL_PATH_NAMES = NO",
        f"STRIP_FROM_PATH = {source_root}",
        "GENERATE_HTML = YES",
        "HTML_OUTPUT = api",
        "GENERATE_LATEX = NO",
        f"HTML_EXTRA_STYLESHEET = {source_root / 'docs/assets/doxygen-extra.css'}",
    ]) + "\n"


def render_doxygen(doxygen: str, source_root: Path, output_root: Path, version: str) -> None:
    configuration = compose_doxygen_configuration(source_root, output_root, version)
    run([doxygen, "-"], cwd=source_root, stdin=configuration)
    if not (output_root / "api/index.html").is_file():
        fail("Doxygen did not produce api/index.html")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--project-version", required=True)
    parser.add_argument("--pandoc", required=True)
    parser.add_argument("--doxygen", required=True)
    parser.add_argument("--checker", type=Path, required=True)
    parser.add_argument("--stamp", type=Path, required=True)
    args = parser.parse_args()

    source_root = args.source_root.resolve()
    output_dir = args.output_dir.resolve()
    stamp = args.stamp.resolve()
    project, documents = load_manifest(args.manifest.resolve())
    pandoc_version(args.pandoc)

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{project}-{args.project_version}-", dir=output_dir.parent))
    try:
        assets = temporary / "assets"
        assets.mkdir(parents=True)
        shutil.copy2(source_root / "docs/assets/house.css", assets / "house.css")
        shutil.copy2(source_root / "docs/assets/doxygen-extra.css", assets / "doxygen-extra.css")
        legal = temporary / "legal"
        legal.mkdir()
        shutil.copy2(source_root / "COPYING", legal / "COPYING")
        shutil.copy2(source_root / "COPYRIGHT", legal / "COPYRIGHT")
        render_markdown(args.pandoc, source_root, temporary, project, args.project_version, documents)
        render_doxygen(args.doxygen, source_root, temporary, args.project_version)
        run([
            sys.executable,
            str(args.checker),
            str(temporary),
            "--manifest",
            str(args.manifest.resolve()),
            "--forbid-path",
            str(source_root),
            "--forbid-path",
            str(output_dir.parent),
        ])
        if output_dir.exists():
            shutil.rmtree(output_dir)
        temporary.rename(output_dir)
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.write_text(f"{project} {args.project_version}\n", encoding="utf-8", newline="\n")
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
