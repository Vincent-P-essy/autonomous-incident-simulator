"""Filesystem exporters kept outside the pure simulation core."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Dict, List, Mapping

from .serialization import canonical_json, digest, pretty_json


_EXPORT_NAMESPACE = uuid.UUID("af727c74-804a-48bb-8663-137cadde8828")


def telemetry_jsonl(report: Mapping[str, Any]) -> str:
    return "\n".join(canonical_json(event) for event in report["telemetry"]) + "\n"


def stix_like_bundle(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Create a deterministic STIX-inspired interchange bundle.

    The explicit custom type and conformance warning prevent consumers from
    confusing this educational export with a validated STIX 2.1 document.
    """

    scenario_id = report["scenario"]["id"]
    objects: List[Dict[str, Any]] = []
    incident_id = f"x-simulated-incident--{uuid.uuid5(_EXPORT_NAMESPACE, scenario_id)}"
    objects.append(
        {
            "type": "x-simulated-incident",
            "id": incident_id,
            "name": report["scenario"]["title"],
            "objective": report["scenario"]["objective"],
            "seed": report["simulation"]["seed"],
            "created": report["simulation"]["start_time"],
            "modified": report["simulation"]["end_time"],
        }
    )
    for technique in report["ground_truth"]["techniques"]:
        technique_id = technique["technique_id"]
        object_id = f"attack-pattern--{uuid.uuid5(_EXPORT_NAMESPACE, technique_id)}"
        objects.append(
            {
                "type": "attack-pattern",
                "id": object_id,
                "name": technique["technique_name"],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique_id,
                        "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                    }
                ],
            }
        )
        objects.append(
            {
                "type": "relationship",
                "id": f"relationship--{uuid.uuid5(_EXPORT_NAMESPACE, scenario_id + technique_id)}",
                "relationship_type": "uses",
                "source_ref": incident_id,
                "target_ref": object_id,
            }
        )
    for step in report["plan"]["steps"]:
        step_events = [
            event
            for event in report["telemetry"]
            if event["step_index"] == step["index"]
        ]
        objects.append(
            {
                "type": "observed-data",
                "id": f"observed-data--{uuid.uuid5(_EXPORT_NAMESPACE, scenario_id + str(step['index']))}",
                "first_observed": min(event["timestamp"] for event in step_events),
                "last_observed": max(event["timestamp"] for event in step_events),
                "number_observed": len(step_events),
                "x_simulator_event_refs": [event["event_id"] for event in step_events],
            }
        )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_EXPORT_NAMESPACE, scenario_id + str(report['simulation']['seed']))}",
        "spec_version": "2.1-inspired",
        "x_conformance": "not validated as STIX 2.1; custom educational export",
        "objects": objects,
    }


def markdown_summary(report: Mapping[str, Any]) -> str:
    metrics = report["metrics"]
    lines = [
        f"# {report['scenario']['title']}",
        "",
        f"- Scenario: `{report['scenario']['id']}`",
        f"- Seed: `{report['simulation']['seed']}`",
        f"- Duration simulated: `{report['simulation']['duration_seconds']} s`",
        f"- Techniques: `{metrics['technique_count']}`",
        f"- Events: `{metrics['event_count']}` from `{metrics['telemetry_source_count']}` sources",
        f"- Report SHA-256: `{digest(report)}`",
        "",
        "## Plan",
        "",
        "| # | Primitive | Technique | Duration |",
        "|---:|---|---|---:|",
    ]
    for step in report["plan"]["steps"]:
        lines.append(
            f"| {step['index']} | `{step['primitive_id']}` | {step['technique_id']} | {step['duration_seconds']} s |"
        )
    lines.extend(["", "## Detection criteria", ""])
    for item in report["detection_results"]:
        lines.append(f"- {'PASS' if item['matched'] else 'FAIL'} — {item['title']}")
    lines.extend(
        [
            "",
            "## Safety",
            "",
            "This report was produced by pure state transitions; no external action was performed.",
            "",
        ]
    )
    return "\n".join(lines)


def write_artifacts(report: Mapping[str, Any], output_dir: Path) -> Dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "report": output_dir / "report.json",
        "telemetry": output_dir / "telemetry.jsonl",
        "ground_truth": output_dir / "ground-truth.json",
        "stix_like": output_dir / "bundle.stix-like.json",
        "summary": output_dir / "summary.md",
    }
    files["report"].write_text(pretty_json(report), encoding="utf-8")
    files["telemetry"].write_text(telemetry_jsonl(report), encoding="utf-8")
    files["ground_truth"].write_text(
        pretty_json(report["ground_truth"]), encoding="utf-8"
    )
    files["stix_like"].write_text(
        pretty_json(stix_like_bundle(report)), encoding="utf-8"
    )
    files["summary"].write_text(markdown_summary(report), encoding="utf-8")
    return {name: str(path) for name, path in files.items()}
