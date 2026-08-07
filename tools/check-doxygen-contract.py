#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import concurrent.futures
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

FUNCTION_KINDS = {
    "FunctionDecl",
    "CXXMethodDecl",
    "CXXConstructorDecl",
    "CXXDestructorDecl",
    "ConversionFunctionDecl",
}
CONTAINER_KINDS = {
    "NamespaceDecl",
    "LinkageSpecDecl",
    "FunctionTemplateDecl",
    "ClassTemplateSpecializationDecl",
    "FriendDecl",
}


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"doxygen-contract: {message}")


def decode_json_stream(text: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    cursor = 0
    documents: list[dict[str, Any]] = []
    while cursor < len(text):
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor >= len(text):
            break
        document, cursor = decoder.raw_decode(text, cursor)
        if not isinstance(document, dict):
            fail("Clang emitted a non-object AST document")
        documents.append(document)
    return documents


def run_clang(
    clang: str,
    include_roots: list[Path],
    namespace: str,
    header: Path,
) -> tuple[Path, list[dict[str, Any]]]:
    command = [
        clang,
        "-x",
        "c++",
        "-std=c++17",
        "-fsyntax-only",
        "-fparse-all-comments",
    ]
    for include_root in include_roots:
        command.append(f"-I{include_root}")
    command += [
        "-Xclang",
        "-ast-dump=json",
        "-Xclang",
        f"-ast-dump-filter={namespace}",
        str(header),
    ]
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        fail(
            f"Clang failed for {header.name}: "
            f"{' '.join(command)}\n{completed.stderr.strip()}"
        )
    return header, decode_json_stream(completed.stdout)


def nested(node: dict[str, Any]) -> Iterable[dict[str, Any]]:
    yield node
    for child in node.get("inner", []):
        if isinstance(child, dict):
            yield from nested(child)


def full_comment(node: dict[str, Any]) -> dict[str, Any] | None:
    for child in node.get("inner", []):
        if isinstance(child, dict) and child.get("kind") == "FullComment":
            return child
    return None


def comment_contract(comment: dict[str, Any] | None) -> tuple[set[str], bool]:
    parameters: set[str] = set()
    has_return = False
    if comment is None:
        return parameters, has_return
    for node in nested(comment):
        kind = node.get("kind")
        if kind == "ParamCommandComment":
            name = node.get("param")
            if isinstance(name, str):
                parameters.add(name)
        elif kind in {"ReturnsCommandComment", "ReturnCommandComment"}:
            has_return = True
        elif kind == "BlockCommandComment" and node.get("name") in {
            "return",
            "returns",
            "retval",
        }:
            has_return = True
    return parameters, has_return


def preferred_file(location: Any) -> str | None:
    if not isinstance(location, dict):
        return None
    expansion = location.get("expansionLoc")
    if isinstance(expansion, dict):
        value = preferred_file(expansion)
        if value is not None:
            return value
    value = location.get("file")
    if isinstance(value, str):
        return value
    spelling = location.get("spellingLoc")
    if isinstance(spelling, dict):
        return preferred_file(spelling)
    return None


def has_included_from(location: Any) -> bool:
    if not isinstance(location, dict):
        return False
    if "includedFrom" in location:
        return True
    return any(
        has_included_from(location.get(name))
        for name in ("expansionLoc", "spellingLoc")
    )


def belongs_to_header(node: dict[str, Any], header: Path) -> bool:
    location = node.get("loc", {})
    value = preferred_file(location)
    if value is not None:
        return Path(value).resolve() == header.resolve()
    return not has_included_from(location)


def declaration_line(node: dict[str, Any]) -> int | str:
    value = node.get("loc", {}).get("line")
    return value if isinstance(value, int) else "?"


def documented_before(header: Path, line: int | str) -> bool:
    if not isinstance(line, int):
        return False
    lines = header.read_text(encoding="utf-8").splitlines()
    cursor = line - 2
    while cursor >= 0 and not lines[cursor].strip():
        cursor -= 1
    while cursor >= 0 and not lines[cursor].strip().endswith("*/"):
        cursor -= 1
    if cursor < 0:
        return False
    while cursor >= 0:
        if "/**" in lines[cursor] or "/*!" in lines[cursor]:
            return True
        if "/*" in lines[cursor]:
            return False
        cursor -= 1
    return False


def function_issues(node: dict[str, Any], header: Path) -> list[str]:
    if node.get("explicitlyDeleted"):
        return []
    name = str(node.get("name", "<unnamed>"))
    line = declaration_line(node)
    comment = full_comment(node)
    if comment is None:
        if documented_before(header, line):
            return []
        return [f"{header.name}:{line}: undocumented function {name}"]

    documented_parameters, has_return = comment_contract(comment)
    declared_parameters = {
        str(child["name"])
        for child in node.get("inner", [])
        if isinstance(child, dict)
        and child.get("kind") == "ParmVarDecl"
        and isinstance(child.get("name"), str)
    }
    issues = [
        f"{header.name}:{line}: {name} lacks \\param {parameter}"
        for parameter in sorted(declared_parameters - documented_parameters)
    ]
    issues.extend(
        f"{header.name}:{line}: {name} documents nonexistent \\param {parameter}"
        for parameter in sorted(documented_parameters - declared_parameters)
    )

    kind = node.get("kind")
    qualified_type = str(node.get("type", {}).get("qualType", ""))
    return_type = qualified_type.split(" (", 1)[0]
    if (
        kind not in {"CXXConstructorDecl", "CXXDestructorDecl"}
        and return_type != "void"
        and not has_return
    ):
        issues.append(f"{header.name}:{line}: {name} lacks \\return")
    return issues


def inspect_nodes(
    nodes: Iterable[dict[str, Any]],
    header: Path,
    access: str = "public",
) -> list[str]:
    issues: list[str] = []
    current_access = access
    for node in nodes:
        kind = node.get("kind")
        if kind == "AccessSpecDecl":
            value = node.get("access")
            if isinstance(value, str):
                current_access = value
            continue

        if kind in {"CXXRecordDecl", "ClassTemplateDecl"}:
            if not belongs_to_header(node, header):
                continue
            default_access = "public" if node.get("tagUsed") == "struct" else "private"
            issues.extend(inspect_nodes(node.get("inner", []), header, default_access))
            if (
                current_access != "private"
                and node.get("name")
                and not node.get("isImplicit")
                and node.get("completeDefinition")
                and full_comment(node) is None
            ):
                issues.append(
                    f"{header.name}:{declaration_line(node)}: "
                    f"undocumented record {node.get('name')}"
                )
            continue

        if kind in CONTAINER_KINDS:
            issues.extend(inspect_nodes(node.get("inner", []), header, current_access))
            continue

        if (
            current_access == "private"
            or not belongs_to_header(node, header)
            or node.get("isImplicit")
        ):
            continue

        if kind in FUNCTION_KINDS:
            issues.extend(function_issues(node, header))
        elif kind in {"TypeAliasDecl", "TypedefDecl", "VarDecl", "FieldDecl"}:
            name = node.get("name")
            if name and full_comment(node) is None:
                issues.append(
                    f"{header.name}:{declaration_line(node)}: "
                    f"undocumented {kind} {name}"
                )
    return issues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--include-subdir", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument(
        "--include-root",
        action="append",
        default=[],
        type=Path,
        help="additional public dependency include root",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    include_root = root / "include"
    include_roots = [include_root] + [path.resolve() for path in args.include_root]
    header_root = include_root / args.include_subdir
    headers = sorted(header_root.glob("*.h"))
    if not headers:
        fail(f"no public headers under {header_root}")

    parsed: list[tuple[Path, list[dict[str, Any]]]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [
            executor.submit(
                run_clang,
                args.clang,
                include_roots,
                args.namespace,
                header,
            )
            for header in headers
        ]
        for future in concurrent.futures.as_completed(futures):
            parsed.append(future.result())

    issues: list[str] = []
    for header, documents in parsed:
        issues.extend(inspect_nodes(documents, header))
    if issues:
        for issue in sorted(set(issues)):
            print(f"doxygen-contract: {issue}", file=sys.stderr)
        return 1

    print("doxygen-contract: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
