from __future__ import annotations

import unittest
from dataclasses import replace

from incident_simulator.catalog import CATALOG, all_primitives
from incident_simulator.dsl import load_scenario
from incident_simulator.errors import PlanningError
from incident_simulator.metrics import benchmark
from incident_simulator.planner import build_plan
from incident_simulator.serialization import digest
from incident_simulator.simulator import simulate
from incident_simulator.topology import generate_topology

from .helpers import EXAMPLES


class EngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = load_scenario(EXAMPLES / "payroll-no-malware.json")

    def test_topology_is_seeded_and_uses_documentation_addresses(self) -> None:
        first = generate_topology(self.spec.topology, self.spec.seed)
        second = generate_topology(self.spec.topology, self.spec.seed)
        changed = generate_topology(self.spec.topology, self.spec.seed + 1)
        self.assertEqual(first, second)
        self.assertNotEqual(first.assets[0].id, changed.assets[0].id)
        self.assertTrue(first.documentation_only_addresses)
        self.assertTrue(
            all(
                asset.address.startswith(("192.0.2.", "198.51.100.", "203.0.113."))
                for asset in first.assets
            )
        )

    def test_plan_satisfies_all_declared_constraints(self) -> None:
        topology = generate_topology(self.spec.topology, self.spec.seed)
        plan = build_plan(self.spec, topology)
        techniques = {step.technique_id for step in plan.steps}
        self.assertLessEqual(
            plan.total_duration_seconds, self.spec.constraints.max_duration_seconds
        )
        self.assertLessEqual(len(plan.steps), self.spec.constraints.max_steps)
        self.assertGreaterEqual(len(techniques), self.spec.constraints.min_techniques)
        self.assertTrue(
            set(self.spec.constraints.required_techniques).issubset(techniques)
        )
        self.assertTrue(
            all(
                step.primitive_id in self.spec.constraints.allowed_primitives
                for step in plan.steps
            )
        )
        self.assertIn(self.spec.objective.kind.required_fact, plan.final_facts)

    def test_impossible_duration_fails_closed(self) -> None:
        constrained = replace(
            self.spec,
            constraints=replace(self.spec.constraints, max_duration_seconds=1),
        )
        topology = generate_topology(constrained.topology, constrained.seed)
        with self.assertRaises(PlanningError):
            build_plan(constrained, topology)

    def test_same_input_has_same_report_digest(self) -> None:
        first = simulate(self.spec)
        second = simulate(self.spec)
        self.assertEqual(first, second)
        self.assertEqual(digest(first), digest(second))

    def test_every_example_meets_coverage_and_safety_contracts(self) -> None:
        for path in sorted(EXAMPLES.glob("*.json")):
            with self.subTest(path=path.name):
                report = simulate(load_scenario(path))
                self.assertEqual(1.0, report["metrics"]["required_technique_coverage"])
                self.assertEqual(1.0, report["metrics"]["required_source_coverage"])
                self.assertEqual(
                    1.0, report["metrics"]["detection_criterion_pass_rate"]
                )
                self.assertEqual(1.0, report["metrics"]["expected_result_pass_rate"])
                self.assertFalse(report["safety"]["external_side_effects"])
                self.assertFalse(report["safety"]["process_execution"])
                self.assertFalse(report["safety"]["real_network_activity"])
                self.assertEqual(
                    [], report["safety"]["forbidden_capabilities_observed"]
                )
                expected_objective_fact = (
                    "objective.asset_compromised"
                    if report["scenario"]["objective"]["kind"] == "compromise_asset"
                    else "objective.data_collected"
                )
                self.assertEqual(
                    expected_objective_fact, report["ground_truth"]["objective_fact"]
                )

    def test_telemetry_is_multi_source_ordered_and_uniquely_identified(self) -> None:
        report = simulate(self.spec)
        events = report["telemetry"]
        self.assertGreaterEqual(len({event["source"] for event in events}), 5)
        self.assertEqual(len(events), len({event["event_id"] for event in events}))
        self.assertEqual(
            events,
            sorted(events, key=lambda event: (event["timestamp"], event["event_id"])),
        )
        self.assertTrue(all(event["attributes"]["simulation"] for event in events))

    def test_catalog_has_unique_identifiers_and_only_inert_capabilities(self) -> None:
        primitives = all_primitives()
        self.assertEqual(len(primitives), len(CATALOG))
        self.assertEqual(
            len(primitives), len({item.technique_id + item.id for item in primitives})
        )
        for primitive in primitives:
            self.assertIn("simulated_only", primitive.capabilities)
            self.assertGreaterEqual(primitive.min_duration_seconds, 1)
            self.assertGreaterEqual(
                primitive.max_duration_seconds, primitive.min_duration_seconds
            )
            self.assertTrue(primitive.telemetry)

    def test_benchmark_proves_determinism(self) -> None:
        result = benchmark(self.spec, runs=4)
        self.assertTrue(result["deterministic"])
        self.assertEqual(1, result["unique_output_digests"])
        self.assertEqual(1.0, result["coverage"]["detection_criteria"])
        self.assertGreater(result["latency_ms"]["max"], 0)


if __name__ == "__main__":
    unittest.main()
