"""Pure execution engine producing synthetic telemetry and ground truth."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Sequence

from . import __version__
from .catalog import CATALOG
from .models import Plan, ScenarioSpec, Topology, isoformat_utc, to_jsonable
from .planner import build_plan
from .topology import generate_topology


_ID_NAMESPACE = uuid.UUID("77483a04-2144-4ca7-b683-25aa980649ef")


def _stable_id(kind: str, *parts: object) -> str:
    material = ":".join(str(part) for part in (kind,) + parts)
    return f"{kind}-{uuid.uuid5(_ID_NAMESPACE, material)}"


def _event_time(
    step_start: datetime, duration: int, index: int, count: int
) -> datetime:
    offset = max(1, round(duration * (index + 1) / (count + 1)))
    return step_start + timedelta(seconds=min(offset, duration))


def _build_events(
    spec: ScenarioSpec, topology: Topology, plan: Plan
) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    step_start = spec.start_time.astimezone(timezone.utc)
    actor = topology.identities[0]
    trace_id = _stable_id("trace", spec.id, spec.seed)
    for step in plan.steps:
        primitive = CATALOG[step.primitive_id]
        for event_index, template in enumerate(primitive.telemetry):
            event_id = _stable_id(
                "event", spec.id, spec.seed, step.index, event_index, template.source
            )
            attributes = dict(template.attributes)
            attributes.update(
                {
                    "simulation": True,
                    "target_role": plan.target_role,
                    "primitive_id": primitive.id,
                }
            )
            events.append(
                {
                    "event_id": event_id,
                    "timestamp": isoformat_utc(
                        _event_time(
                            step_start,
                            step.duration_seconds,
                            event_index,
                            len(primitive.telemetry),
                        )
                    ),
                    "source": template.source,
                    "event_type": template.event_type,
                    "outcome": template.outcome,
                    "actor": {
                        "identity_id": actor.id,
                        "display_name": actor.display_name,
                        "synthetic": True,
                    },
                    "target": {
                        "asset_id": plan.target_asset_id,
                        "role": plan.target_role,
                    },
                    "trace_id": trace_id,
                    "step_index": step.index,
                    "technique": {
                        "id": primitive.technique_id,
                        "name": primitive.technique_name,
                        "tactic": primitive.tactic,
                    },
                    "attributes": attributes,
                }
            )
        step_start += timedelta(seconds=step.duration_seconds)
    return sorted(events, key=lambda event: (event["timestamp"], event["event_id"]))


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _evaluate_criterion(
    criterion: Any, events: Sequence[Mapping[str, Any]]
) -> Dict[str, Any]:
    selected: List[Mapping[str, Any]] = []
    cursor = 0
    for expected_type in criterion.ordered_event_types:
        match = None
        for index in range(cursor, len(events)):
            if events[index]["event_type"] == expected_type:
                match = events[index]
                cursor = index + 1
                break
        if match is None:
            return {
                "criterion_id": criterion.id,
                "title": criterion.title,
                "matched": False,
                "matched_event_ids": [event["event_id"] for event in selected],
                "reason": f"ordered event type not found: {expected_type}",
            }
        selected.append(match)

    sources = {str(event["source"]) for event in selected}
    missing_sources = sorted(set(criterion.required_sources) - sources)
    if missing_sources:
        return {
            "criterion_id": criterion.id,
            "title": criterion.title,
            "matched": False,
            "matched_event_ids": [event["event_id"] for event in selected],
            "reason": "required sources absent from sequence: "
            + ", ".join(missing_sources),
        }

    span = 0
    if len(selected) > 1:
        span = int(
            (
                _parse_timestamp(selected[-1]["timestamp"])
                - _parse_timestamp(selected[0]["timestamp"])
            ).total_seconds()
        )
    matched = (
        len(selected) >= criterion.minimum_matching_events
        and span <= criterion.max_span_seconds
    )
    return {
        "criterion_id": criterion.id,
        "title": criterion.title,
        "matched": matched,
        "matched_event_ids": [event["event_id"] for event in selected],
        "span_seconds": span,
        "reason": "sequence matched"
        if matched
        else "sequence failed count or time-window constraint",
    }


def _evaluate_expected_result(
    expectation: Any,
    spec: ScenarioSpec,
    plan: Plan,
    events: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    techniques = {step.technique_id for step in plan.steps}
    sources = {str(event["source"]) for event in events}
    capabilities = {
        capability
        for step in plan.steps
        for capability in CATALOG[step.primitive_id].capabilities
    }
    if expectation.kind == "objective_reached":
        actual: Any = spec.objective.kind.required_fact in plan.final_facts
    elif expectation.kind == "minimum_techniques":
        actual = len(techniques)
    elif expectation.kind == "telemetry_source_present":
        actual = str(expectation.value) in sources
    elif expectation.kind == "forbidden_capability_absent":
        actual = str(expectation.value) not in capabilities
    elif expectation.kind == "duration_at_most":
        actual = plan.total_duration_seconds
    else:  # Defensive guard; the DSL rejects this earlier.
        actual = None

    if expectation.kind in {"minimum_techniques"}:
        passed = actual >= int(expectation.value)
    elif expectation.kind == "duration_at_most":
        passed = actual <= int(expectation.value)
    else:
        passed = (
            actual == expectation.value
            if expectation.kind == "objective_reached"
            else bool(actual)
        )
    return {
        "expectation_id": expectation.id,
        "title": expectation.title,
        "kind": expectation.kind,
        "expected": expectation.value,
        "actual": actual,
        "passed": passed,
    }


def _ground_truth(spec: ScenarioSpec, plan: Plan) -> Dict[str, Any]:
    techniques: Dict[str, Dict[str, Any]] = {}
    for step in plan.steps:
        item = techniques.setdefault(
            step.technique_id,
            {
                "technique_id": step.technique_id,
                "technique_name": step.technique_name,
                "tactics": [],
                "step_indexes": [],
            },
        )
        if step.tactic not in item["tactics"]:
            item["tactics"].append(step.tactic)
        item["step_indexes"].append(step.index)
    return {
        "framework": "MITRE ATT&CK Enterprise",
        "mapping_status": "curated snapshot; identifiers require periodic upstream review",
        "techniques": [techniques[key] for key in sorted(techniques)],
        "objective_fact": spec.objective.kind.required_fact,
    }


def simulate(
    spec: ScenarioSpec, topology: Topology | None = None, plan: Plan | None = None
) -> Dict[str, Any]:
    """Run a side-effect-free scenario and return a deterministic report."""

    actual_topology = topology or generate_topology(spec.topology, spec.seed)
    actual_plan = plan or build_plan(spec, actual_topology)
    events = _build_events(spec, actual_topology, actual_plan)
    criterion_results = [
        _evaluate_criterion(criterion, events) for criterion in spec.detection_criteria
    ]
    expectation_results = [
        _evaluate_expected_result(expectation, spec, actual_plan, events)
        for expectation in spec.expected_results
    ]
    observed_techniques = {step.technique_id for step in actual_plan.steps}
    observed_sources = {event["source"] for event in events}
    required_techniques = set(spec.constraints.required_techniques)
    required_sources = set(spec.constraints.required_telemetry_sources)
    used_capabilities = sorted(
        {
            capability
            for step in actual_plan.steps
            for capability in CATALOG[step.primitive_id].capabilities
        }
    )
    forbidden_observed = sorted(
        set(spec.constraints.forbidden_capabilities) & set(used_capabilities)
    )
    end_time = spec.start_time + timedelta(seconds=actual_plan.total_duration_seconds)
    return {
        "report_version": "1.0",
        "engine": {"name": "autonomous-incident-simulator", "version": __version__},
        "scenario": to_jsonable(spec),
        "simulation": {
            "mode": "pure-deterministic-state-transition",
            "seed": spec.seed,
            "start_time": isoformat_utc(spec.start_time),
            "end_time": isoformat_utc(end_time),
            "duration_seconds": actual_plan.total_duration_seconds,
        },
        "topology": to_jsonable(actual_topology),
        "plan": to_jsonable(actual_plan),
        "telemetry": events,
        "ground_truth": _ground_truth(spec, actual_plan),
        "detection_results": criterion_results,
        "expected_results": expectation_results,
        "analyst_questions": to_jsonable(spec.analyst_questions),
        "metrics": {
            "event_count": len(events),
            "telemetry_source_count": len(observed_sources),
            "technique_count": len(observed_techniques),
            "required_technique_coverage": (
                len(required_techniques & observed_techniques)
                / len(required_techniques)
                if required_techniques
                else 1.0
            ),
            "required_source_coverage": len(required_sources & observed_sources)
            / len(required_sources),
            "detection_criterion_pass_rate": sum(
                item["matched"] for item in criterion_results
            )
            / len(criterion_results),
            "expected_result_pass_rate": sum(
                item["passed"] for item in expectation_results
            )
            / len(expectation_results),
        },
        "safety": {
            "external_side_effects": False,
            "real_network_activity": False,
            "process_execution": False,
            "arbitrary_actions_accepted": False,
            "catalog_only": True,
            "used_capabilities": used_capabilities,
            "forbidden_capabilities_observed": forbidden_observed,
        },
    }
