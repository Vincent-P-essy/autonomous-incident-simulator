"""Immutable typed models used by every engine layer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, List, Mapping, Tuple


class ObjectiveKind(str, Enum):
    COMPROMISE_ASSET = "compromise_asset"
    COLLECT_SENSITIVE_DATA = "collect_sensitive_data"

    @property
    def required_fact(self) -> str:
        if self is ObjectiveKind.COMPROMISE_ASSET:
            return "objective.asset_compromised"
        return "objective.data_collected"


@dataclass(frozen=True)
class Objective:
    kind: ObjectiveKind
    target_role: str
    description: str


@dataclass(frozen=True)
class Constraints:
    max_duration_seconds: int
    max_steps: int
    min_techniques: int
    required_techniques: Tuple[str, ...]
    allowed_primitives: Tuple[str, ...]
    forbidden_capabilities: Tuple[str, ...]
    required_telemetry_sources: Tuple[str, ...]


@dataclass(frozen=True)
class TopologyRequest:
    profile: str
    required_roles: Tuple[str, ...]
    user_count: int


@dataclass(frozen=True)
class DetectionCriterion:
    id: str
    title: str
    ordered_event_types: Tuple[str, ...]
    required_sources: Tuple[str, ...]
    max_span_seconds: int
    minimum_matching_events: int


@dataclass(frozen=True)
class ExpectedResult:
    id: str
    title: str
    kind: str
    value: Any


@dataclass(frozen=True)
class AnalystQuestion:
    id: str
    prompt: str
    evidence_hints: Tuple[str, ...]


@dataclass(frozen=True)
class ScenarioSpec:
    schema_version: str
    id: str
    title: str
    description: str
    seed: int
    start_time: datetime
    objective: Objective
    constraints: Constraints
    topology: TopologyRequest
    detection_criteria: Tuple[DetectionCriterion, ...]
    expected_results: Tuple[ExpectedResult, ...]
    analyst_questions: Tuple[AnalystQuestion, ...]


@dataclass(frozen=True)
class PrimitiveTelemetry:
    source: str
    event_type: str
    outcome: str
    attributes: Tuple[Tuple[str, Any], ...] = ()


@dataclass(frozen=True)
class Primitive:
    id: str
    title: str
    technique_id: str
    technique_name: str
    tactic: str
    requires: Tuple[str, ...]
    effects: Tuple[str, ...]
    capabilities: Tuple[str, ...]
    min_duration_seconds: int
    max_duration_seconds: int
    telemetry: Tuple[PrimitiveTelemetry, ...]


@dataclass(frozen=True)
class Asset:
    id: str
    role: str
    hostname: str
    operating_system: str
    zone: str
    address: str
    criticality: str
    services: Tuple[str, ...]


@dataclass(frozen=True)
class Identity:
    id: str
    display_name: str
    privilege: str
    home_asset_id: str


@dataclass(frozen=True)
class NetworkFlow:
    source_asset_id: str
    destination_asset_id: str
    service: str
    policy: str


@dataclass(frozen=True)
class Topology:
    profile: str
    assets: Tuple[Asset, ...]
    identities: Tuple[Identity, ...]
    allowed_flows: Tuple[NetworkFlow, ...]
    documentation_only_addresses: bool = True


@dataclass(frozen=True)
class PlannedStep:
    index: int
    primitive_id: str
    primitive_title: str
    technique_id: str
    technique_name: str
    tactic: str
    duration_seconds: int
    target_asset_id: str
    facts_before: Tuple[str, ...]
    facts_after: Tuple[str, ...]


@dataclass(frozen=True)
class Plan:
    scenario_id: str
    seed: int
    target_asset_id: str
    target_role: str
    steps: Tuple[PlannedStep, ...]
    total_duration_seconds: int
    final_facts: Tuple[str, ...]


def isoformat_utc(value: datetime) -> str:
    """Render timestamps in one canonical UTC representation."""

    normalized = value.astimezone(timezone.utc)
    return normalized.isoformat(timespec="seconds").replace("+00:00", "Z")


def to_jsonable(value: Any) -> Any:
    """Convert immutable models into deterministic JSON-compatible values."""

    if isinstance(value, datetime):
        return isoformat_utc(value)
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {key: to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [to_jsonable(item) for item in value]
    return value


def unique_preserving_order(values: Iterable[str]) -> Tuple[str, ...]:
    seen = set()
    ordered: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return tuple(ordered)
