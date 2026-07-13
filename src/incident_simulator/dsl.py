"""Parser and semantic validator for version 1.0 of the scenario DSL."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence, Set, Tuple

from .catalog import CATALOG, known_event_types, known_sources
from .errors import ValidationError
from .models import (
    AnalystQuestion,
    Constraints,
    DetectionCriterion,
    ExpectedResult,
    Objective,
    ObjectiveKind,
    ScenarioSpec,
    TopologyRequest,
)
from .topology import profile_roles, supported_profiles, supported_roles


SCHEMA_VERSION = "1.0"
_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_TECHNIQUE_PATTERN = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_UNSAFE_FIELD_NAMES = {
    "action",
    "command",
    "commands",
    "code",
    "exec",
    "executable",
    "network_request",
    "payload",
    "raw_action",
    "script",
    "shell",
    "subprocess",
    "tool_call",
}


def _reject_unsafe_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if str(key).lower() in _UNSAFE_FIELD_NAMES:
                raise ValidationError(
                    f"free-form executable field is prohibited at {path}.{key}"
                )
            _reject_unsafe_fields(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_unsafe_fields(nested, f"{path}[{index}]")


def _object(
    value: Any, path: str, required: Set[str], optional: Set[str] = set()
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} must be an object")
    keys = set(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise ValidationError(f"{path} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValidationError(
            f"{path} contains unsupported fields: {', '.join(sorted(unknown))}"
        )
    return value


def _string(value: Any, path: str, minimum: int = 1, maximum: int = 500) -> str:
    if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
        raise ValidationError(
            f"{path} must be a string between {minimum} and {maximum} characters"
        )
    return value.strip()


def _integer(value: Any, path: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ValidationError(
            f"{path} must be an integer between {minimum} and {maximum}"
        )
    return int(value)


def _string_list(
    value: Any, path: str, minimum: int = 0, unique: bool = True
) -> Tuple[str, ...]:
    if not isinstance(value, list) or len(value) < minimum:
        raise ValidationError(f"{path} must be a list with at least {minimum} entries")
    parsed = tuple(
        _string(item, f"{path}[{index}]", maximum=120)
        for index, item in enumerate(value)
    )
    if unique and len(set(parsed)) != len(parsed):
        raise ValidationError(f"{path} must not contain duplicates")
    return parsed


def _parse_time(value: Any, path: str) -> datetime:
    text = _string(value, path, maximum=40)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{path} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{path} must include a timezone")
    return parsed


def _parse_objective(value: Any) -> Objective:
    data = _object(value, "$.objective", {"kind", "target_role", "description"})
    try:
        kind = ObjectiveKind(_string(data["kind"], "$.objective.kind", maximum=64))
    except ValueError as exc:
        allowed = ", ".join(item.value for item in ObjectiveKind)
        raise ValidationError(f"$.objective.kind must be one of: {allowed}") from exc
    target_role = _string(data["target_role"], "$.objective.target_role", maximum=64)
    if target_role not in supported_roles():
        raise ValidationError(f"unsupported objective target role: {target_role}")
    return Objective(
        kind=kind,
        target_role=target_role,
        description=_string(
            data["description"], "$.objective.description", maximum=500
        ),
    )


def _parse_constraints(value: Any) -> Constraints:
    required = {
        "max_duration_seconds",
        "max_steps",
        "min_techniques",
        "required_techniques",
        "allowed_primitives",
        "forbidden_capabilities",
        "required_telemetry_sources",
    }
    data = _object(value, "$.constraints", required)
    allowed_primitives = _string_list(
        data["allowed_primitives"], "$.constraints.allowed_primitives", minimum=1
    )
    unknown = sorted(set(allowed_primitives) - set(CATALOG))
    if unknown:
        raise ValidationError(f"unknown primitive identifiers: {', '.join(unknown)}")

    required_techniques = _string_list(
        data["required_techniques"], "$.constraints.required_techniques"
    )
    for technique in required_techniques:
        if not _TECHNIQUE_PATTERN.fullmatch(technique):
            raise ValidationError(f"invalid technique identifier: {technique}")

    available_techniques = {CATALOG[item].technique_id for item in allowed_primitives}
    missing_techniques = sorted(set(required_techniques) - available_techniques)
    if missing_techniques:
        raise ValidationError(
            "required techniques have no allowed primitive: "
            + ", ".join(missing_techniques)
        )

    forbidden = _string_list(
        data["forbidden_capabilities"], "$.constraints.forbidden_capabilities"
    )
    conflicts = sorted(
        {
            capability
            for primitive_id in allowed_primitives
            for capability in CATALOG[primitive_id].capabilities
            if capability in forbidden
        }
    )
    if conflicts:
        raise ValidationError(
            "allowed primitives expose forbidden capabilities: " + ", ".join(conflicts)
        )

    required_sources = _string_list(
        data["required_telemetry_sources"],
        "$.constraints.required_telemetry_sources",
        minimum=1,
    )
    unavailable_sources = sorted(
        set(required_sources) - set(known_sources(allowed_primitives))
    )
    if unavailable_sources:
        raise ValidationError(
            "required telemetry sources cannot be emitted by allowed primitives: "
            + ", ".join(unavailable_sources)
        )

    min_techniques = _integer(
        data["min_techniques"], "$.constraints.min_techniques", 1, 50
    )
    if min_techniques > len(available_techniques):
        raise ValidationError(
            "minimum technique count exceeds the allowed catalog coverage"
        )
    return Constraints(
        max_duration_seconds=_integer(
            data["max_duration_seconds"],
            "$.constraints.max_duration_seconds",
            1,
            86_400,
        ),
        max_steps=_integer(data["max_steps"], "$.constraints.max_steps", 1, 50),
        min_techniques=min_techniques,
        required_techniques=required_techniques,
        allowed_primitives=allowed_primitives,
        forbidden_capabilities=forbidden,
        required_telemetry_sources=required_sources,
    )


def _parse_topology(value: Any, objective: Objective) -> TopologyRequest:
    data = _object(value, "$.topology", {"profile", "required_roles", "user_count"})
    profile = _string(data["profile"], "$.topology.profile", maximum=64)
    if profile not in supported_profiles():
        raise ValidationError(f"unsupported topology profile: {profile}")
    roles = _string_list(data["required_roles"], "$.topology.required_roles")
    unknown = sorted(set(roles) - set(supported_roles()))
    if unknown:
        raise ValidationError("unsupported topology roles: " + ", ".join(unknown))
    effective_roles = set(profile_roles(profile)) | set(roles)
    if objective.target_role not in effective_roles:
        raise ValidationError("topology must include the objective target role")
    return TopologyRequest(
        profile=profile,
        required_roles=roles,
        user_count=_integer(data["user_count"], "$.topology.user_count", 1, 200),
    )


def _parse_criteria(
    value: Any, allowed_primitives: Sequence[str]
) -> Tuple[DetectionCriterion, ...]:
    if not isinstance(value, list) or not value:
        raise ValidationError("$.detection_criteria must be a non-empty list")
    available_events = set(known_event_types(allowed_primitives))
    available_sources = set(known_sources(allowed_primitives))
    criteria = []
    for index, raw in enumerate(value):
        path = f"$.detection_criteria[{index}]"
        data = _object(
            raw,
            path,
            {
                "id",
                "title",
                "ordered_event_types",
                "required_sources",
                "max_span_seconds",
                "minimum_matching_events",
            },
        )
        event_types = _string_list(
            data["ordered_event_types"],
            f"{path}.ordered_event_types",
            minimum=1,
            unique=False,
        )
        sources = _string_list(
            data["required_sources"], f"{path}.required_sources", minimum=1
        )
        if set(event_types) - available_events:
            raise ValidationError(
                f"{path} references event types unavailable from allowed primitives"
            )
        if set(sources) - available_sources:
            raise ValidationError(
                f"{path} references sources unavailable from allowed primitives"
            )
        minimum_matching_events = _integer(
            data["minimum_matching_events"],
            f"{path}.minimum_matching_events",
            1,
            100,
        )
        if minimum_matching_events > len(event_types):
            raise ValidationError(
                f"{path}.minimum_matching_events cannot exceed the ordered event sequence length"
            )
        criteria.append(
            DetectionCriterion(
                id=_string(data["id"], f"{path}.id", maximum=64),
                title=_string(data["title"], f"{path}.title", maximum=160),
                ordered_event_types=event_types,
                required_sources=sources,
                max_span_seconds=_integer(
                    data["max_span_seconds"], f"{path}.max_span_seconds", 1, 86_400
                ),
                minimum_matching_events=minimum_matching_events,
            )
        )
    _ensure_unique_ids((item.id for item in criteria), "detection criteria")
    return tuple(criteria)


def _parse_expected_results(value: Any) -> Tuple[ExpectedResult, ...]:
    allowed_kinds = {
        "duration_at_most",
        "forbidden_capability_absent",
        "minimum_techniques",
        "objective_reached",
        "telemetry_source_present",
    }
    if not isinstance(value, list) or not value:
        raise ValidationError("$.expected_results must be a non-empty list")
    results = []
    for index, raw in enumerate(value):
        path = f"$.expected_results[{index}]"
        data = _object(raw, path, {"id", "title", "kind", "value"})
        kind = _string(data["kind"], f"{path}.kind", maximum=64)
        if kind not in allowed_kinds:
            raise ValidationError(f"unsupported expected result kind: {kind}")
        expected_value = data["value"]
        if kind == "objective_reached" and not isinstance(expected_value, bool):
            raise ValidationError(
                f"{path}.value must be a boolean for objective_reached"
            )
        if kind in {"minimum_techniques", "duration_at_most"}:
            if isinstance(expected_value, bool) or not isinstance(expected_value, int):
                raise ValidationError(f"{path}.value must be an integer for {kind}")
            if expected_value < 1:
                raise ValidationError(f"{path}.value must be positive for {kind}")
        if kind in {"telemetry_source_present", "forbidden_capability_absent"}:
            if not isinstance(expected_value, str) or not expected_value.strip():
                raise ValidationError(
                    f"{path}.value must be a non-empty string for {kind}"
                )
        results.append(
            ExpectedResult(
                id=_string(data["id"], f"{path}.id", maximum=64),
                title=_string(data["title"], f"{path}.title", maximum=160),
                kind=kind,
                value=expected_value,
            )
        )
    _ensure_unique_ids((item.id for item in results), "expected results")
    return tuple(results)


def _parse_questions(value: Any) -> Tuple[AnalystQuestion, ...]:
    if not isinstance(value, list) or not value:
        raise ValidationError("$.analyst_questions must be a non-empty list")
    questions = []
    for index, raw in enumerate(value):
        path = f"$.analyst_questions[{index}]"
        data = _object(raw, path, {"id", "prompt", "evidence_hints"})
        questions.append(
            AnalystQuestion(
                id=_string(data["id"], f"{path}.id", maximum=64),
                prompt=_string(data["prompt"], f"{path}.prompt", maximum=500),
                evidence_hints=_string_list(
                    data["evidence_hints"], f"{path}.evidence_hints", minimum=1
                ),
            )
        )
    _ensure_unique_ids((item.id for item in questions), "analyst questions")
    return tuple(questions)


def _ensure_unique_ids(values: Iterable[str], label: str) -> None:
    collected = list(values)
    if len(set(collected)) != len(collected):
        raise ValidationError(f"{label} must have unique identifiers")


def parse_scenario(raw: Any) -> ScenarioSpec:
    """Parse untrusted JSON-compatible data into an immutable scenario."""

    _reject_unsafe_fields(raw)
    data = _object(
        raw,
        "$",
        {
            "schema_version",
            "id",
            "title",
            "description",
            "seed",
            "start_time",
            "objective",
            "constraints",
            "topology",
            "detection_criteria",
            "expected_results",
            "analyst_questions",
        },
    )
    version = _string(data["schema_version"], "$.schema_version", maximum=16)
    if version != SCHEMA_VERSION:
        raise ValidationError(
            f"unsupported schema version: {version}; expected {SCHEMA_VERSION}"
        )
    scenario_id = _string(data["id"], "$.id", maximum=64)
    if not _ID_PATTERN.fullmatch(scenario_id):
        raise ValidationError(
            "$.id must use lowercase letters, digits, dots, dashes, or underscores"
        )
    objective = _parse_objective(data["objective"])
    constraints = _parse_constraints(data["constraints"])
    expected_results = _parse_expected_results(data["expected_results"])
    available_sources = set(known_sources(constraints.allowed_primitives))
    impossible_source_expectations = sorted(
        str(item.value)
        for item in expected_results
        if item.kind == "telemetry_source_present"
        and str(item.value) not in available_sources
    )
    if impossible_source_expectations:
        raise ValidationError(
            "expected telemetry sources cannot be emitted by allowed primitives: "
            + ", ".join(impossible_source_expectations)
        )
    return ScenarioSpec(
        schema_version=version,
        id=scenario_id,
        title=_string(data["title"], "$.title", maximum=160),
        description=_string(data["description"], "$.description", maximum=1000),
        seed=_integer(data["seed"], "$.seed", 0, 2_147_483_647),
        start_time=_parse_time(data["start_time"], "$.start_time"),
        objective=objective,
        constraints=constraints,
        topology=_parse_topology(data["topology"], objective),
        detection_criteria=_parse_criteria(
            data["detection_criteria"], constraints.allowed_primitives
        ),
        expected_results=expected_results,
        analyst_questions=_parse_questions(data["analyst_questions"]),
    )


def load_scenario(path: Path) -> ScenarioSpec:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationError(f"scenario file does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"invalid JSON in {path}: line {exc.lineno}, column {exc.colno}"
        ) from exc
    return parse_scenario(raw)
