"""Deterministic breadth-first planning over the closed primitive catalog."""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass
from typing import FrozenSet, Iterable, List, Sequence, Tuple

from .catalog import CATALOG, get_primitive
from .errors import PlanningError
from .models import Plan, PlannedStep, Primitive, ScenarioSpec, Topology
from .topology import find_asset_by_role


@dataclass(frozen=True)
class _Node:
    facts: FrozenSet[str]
    used_primitives: Tuple[str, ...]
    total_duration: int


def _stable_number(seed: int, *parts: str) -> int:
    material = ":".join((str(seed),) + parts).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def _duration(seed: int, primitive: Primitive, step_index: int) -> int:
    width = primitive.max_duration_seconds - primitive.min_duration_seconds + 1
    return (
        primitive.min_duration_seconds
        + _stable_number(seed, primitive.id, str(step_index), "duration") % width
    )


def _ordered_candidates(
    seed: int, primitive_ids: Sequence[str]
) -> Tuple[Primitive, ...]:
    return tuple(
        CATALOG[item]
        for item in sorted(
            primitive_ids,
            key=lambda item: (_stable_number(seed, item, "order"), item),
        )
    )


def _techniques(used_primitives: Iterable[str]) -> FrozenSet[str]:
    return frozenset(CATALOG[item].technique_id for item in used_primitives)


def _sources(used_primitives: Iterable[str]) -> FrozenSet[str]:
    return frozenset(
        template.source
        for primitive_id in used_primitives
        for template in CATALOG[primitive_id].telemetry
    )


def _is_goal(spec: ScenarioSpec, node: _Node) -> bool:
    techniques = _techniques(node.used_primitives)
    sources = _sources(node.used_primitives)
    return (
        spec.objective.kind.required_fact in node.facts
        and set(spec.constraints.required_techniques).issubset(techniques)
        and len(techniques) >= spec.constraints.min_techniques
        and set(spec.constraints.required_telemetry_sources).issubset(sources)
    )


def build_plan(spec: ScenarioSpec, topology: Topology) -> Plan:
    """Find the shortest safe plan, with seeded ordering for ties and durations."""

    target = find_asset_by_role(topology, spec.objective.target_role)
    candidates = _ordered_candidates(spec.seed, spec.constraints.allowed_primitives)
    initial = _Node(
        facts=frozenset({"entry.ready"}), used_primitives=(), total_duration=0
    )
    queue = deque([initial])
    visited = {(initial.facts, initial.used_primitives)}
    solution = None

    while queue:
        node = queue.popleft()
        if _is_goal(spec, node):
            solution = node
            break
        if len(node.used_primitives) >= spec.constraints.max_steps:
            continue

        for primitive in candidates:
            if primitive.id in node.used_primitives:
                continue
            if not set(primitive.requires).issubset(node.facts):
                continue
            duration = _duration(spec.seed, primitive, len(node.used_primitives) + 1)
            total_duration = node.total_duration + duration
            if total_duration > spec.constraints.max_duration_seconds:
                continue
            next_node = _Node(
                facts=frozenset(set(node.facts) | set(primitive.effects)),
                used_primitives=node.used_primitives + (primitive.id,),
                total_duration=total_duration,
            )
            key = (next_node.facts, next_node.used_primitives)
            if key not in visited:
                visited.add(key)
                queue.append(next_node)

    if solution is None:
        raise PlanningError(
            "no allowlisted plan satisfies the objective, duration, step, technique, and telemetry constraints"
        )

    facts = frozenset({"entry.ready"})
    steps: List[PlannedStep] = []
    for index, primitive_id in enumerate(solution.used_primitives, start=1):
        primitive = get_primitive(primitive_id)
        facts_before = tuple(sorted(facts))
        facts = frozenset(set(facts) | set(primitive.effects))
        steps.append(
            PlannedStep(
                index=index,
                primitive_id=primitive.id,
                primitive_title=primitive.title,
                technique_id=primitive.technique_id,
                technique_name=primitive.technique_name,
                tactic=primitive.tactic,
                duration_seconds=_duration(spec.seed, primitive, index),
                target_asset_id=target.id,
                facts_before=facts_before,
                facts_after=tuple(sorted(facts)),
            )
        )

    return Plan(
        scenario_id=spec.id,
        seed=spec.seed,
        target_asset_id=target.id,
        target_role=target.role,
        steps=tuple(steps),
        total_duration_seconds=sum(step.duration_seconds for step in steps),
        final_facts=tuple(sorted(facts)),
    )
