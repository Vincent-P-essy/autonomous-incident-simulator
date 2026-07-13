"""Reproducibility, latency, and coverage benchmark helpers."""

from __future__ import annotations

import statistics
import time
from typing import Any, Dict, List

from .models import ScenarioSpec
from .serialization import digest
from .simulator import simulate


def _percentile(values: List[float], percentile: float) -> float:
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * percentile)))
    return ordered[rank]


def benchmark(spec: ScenarioSpec, runs: int = 20) -> Dict[str, Any]:
    if not 2 <= runs <= 10_000:
        raise ValueError("runs must be between 2 and 10000")
    latencies_ms: List[float] = []
    digests: List[str] = []
    last_report = None
    for _ in range(runs):
        started = time.perf_counter_ns()
        report = simulate(spec)
        elapsed = (time.perf_counter_ns() - started) / 1_000_000
        latencies_ms.append(elapsed)
        digests.append(digest(report))
        last_report = report
    assert last_report is not None
    return {
        "scenario_id": spec.id,
        "runs": runs,
        "deterministic": len(set(digests)) == 1,
        "unique_output_digests": len(set(digests)),
        "output_sha256": digests[0],
        "latency_ms": {
            "min": round(min(latencies_ms), 3),
            "median": round(statistics.median(latencies_ms), 3),
            "p95": round(_percentile(latencies_ms, 0.95), 3),
            "max": round(max(latencies_ms), 3),
        },
        "coverage": {
            "required_techniques": last_report["metrics"][
                "required_technique_coverage"
            ],
            "required_sources": last_report["metrics"]["required_source_coverage"],
            "detection_criteria": last_report["metrics"][
                "detection_criterion_pass_rate"
            ],
            "expected_results": last_report["metrics"]["expected_result_pass_rate"],
        },
        "event_count": last_report["metrics"]["event_count"],
        "technique_count": last_report["metrics"]["technique_count"],
        "telemetry_source_count": last_report["metrics"]["telemetry_source_count"],
    }
