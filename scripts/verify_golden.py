#!/usr/bin/env python3
"""Regenerate the flagship report and verify the committed golden bundle."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incident_simulator.dsl import load_scenario  # noqa: E402
from incident_simulator.serialization import digest  # noqa: E402
from incident_simulator.simulator import simulate  # noqa: E402


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    directory = ROOT / "datasets" / "golden" / "payroll-no-malware"
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    report = simulate(load_scenario(ROOT / "examples" / "payroll-no-malware.json"))
    checks = {
        "canonical_report": digest(report) == manifest["report_sha256"],
        "report_file": file_sha256(directory / "report.json")
        == manifest["report_file_sha256"],
        "telemetry_file": file_sha256(directory / "telemetry.jsonl")
        == manifest["telemetry_file_sha256"],
        "ground_truth_file": file_sha256(directory / "ground-truth.json")
        == manifest["ground_truth_file_sha256"],
        "stix_like_file": file_sha256(directory / "bundle.stix-like.json")
        == manifest["stix_like_file_sha256"],
        "event_count": report["metrics"]["event_count"] == manifest["event_count"],
        "technique_count": report["metrics"]["technique_count"]
        == manifest["technique_count"],
    }
    passed = all(checks.values())
    print(json.dumps({"passed": passed, "checks": checks}, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
