#!/usr/bin/env python3
"""Reject execution and low-level network surfaces from the runtime package."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import List, Tuple


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "incident_simulator"
FORBIDDEN_MODULE_ROOTS = {
    "ctypes",
    "ftplib",
    "paramiko",
    "requests",
    "socket",
    "subprocess",
    "telnetlib",
}
FORBIDDEN_CALLS = {
    "__import__",
    "compile",
    "eval",
    "exec",
    "os.popen",
    "os.spawnl",
    "os.spawnlp",
    "os.spawnv",
    "os.spawnvp",
    "os.system",
}


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def inspect_file(path: Path) -> List[Tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    findings: List[Tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in FORBIDDEN_MODULE_ROOTS:
                    findings.append((node.lineno, f"forbidden import: {alias.name}"))
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            if root in FORBIDDEN_MODULE_ROOTS:
                findings.append((node.lineno, f"forbidden import: {node.module}"))
        elif isinstance(node, ast.Call):
            called = dotted_name(node.func)
            if called in FORBIDDEN_CALLS:
                findings.append((node.lineno, f"forbidden call: {called}"))
    return findings


def main() -> int:
    findings = []
    for path in sorted(SOURCE.rglob("*.py")):
        for line, detail in inspect_file(path):
            findings.append(
                {"file": str(path.relative_to(ROOT)), "line": line, "detail": detail}
            )
    passed = not findings
    print(
        json.dumps({"passed": passed, "findings": findings}, indent=2, sort_keys=True)
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
