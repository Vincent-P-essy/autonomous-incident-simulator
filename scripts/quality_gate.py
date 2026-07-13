#!/usr/bin/env python3
"""Repository-level deterministic quality gate with no third-party tools."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incident_simulator.dsl import load_scenario  # noqa: E402
from incident_simulator.serialization import digest  # noqa: E402
from incident_simulator.simulator import simulate  # noqa: E402


def main() -> int:
    results = []
    for path in sorted((ROOT / "examples").glob("*.json")):
        spec = load_scenario(path)
        first = simulate(spec)
        second = simulate(spec)
        checks = {
            "deterministic": digest(first) == digest(second),
            "all_detection_criteria_pass": first["metrics"][
                "detection_criterion_pass_rate"
            ]
            == 1.0,
            "all_expected_results_pass": first["metrics"]["expected_result_pass_rate"]
            == 1.0,
            "required_techniques_covered": first["metrics"][
                "required_technique_coverage"
            ]
            == 1.0,
            "required_sources_covered": first["metrics"]["required_source_coverage"]
            == 1.0,
            "no_forbidden_capability": not first["safety"][
                "forbidden_capabilities_observed"
            ],
            "no_external_side_effect": not first["safety"]["external_side_effects"],
        }
        results.append(
            {
                "scenario_id": spec.id,
                "report_sha256": digest(first),
                "event_count": first["metrics"]["event_count"],
                "technique_count": first["metrics"]["technique_count"],
                "checks": checks,
            }
        )
    passed = bool(results) and all(all(item["checks"].values()) for item in results)
    print(
        json.dumps({"passed": passed, "scenarios": results}, indent=2, sort_keys=True)
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
