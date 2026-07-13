from __future__ import annotations

import copy
import unittest

from incident_simulator.dsl import load_scenario, parse_scenario
from incident_simulator.errors import ValidationError

from .helpers import EXAMPLES, raw_scenario


class ScenarioDslTests(unittest.TestCase):
    def test_every_example_is_valid(self) -> None:
        scenarios = [load_scenario(path) for path in sorted(EXAMPLES.glob("*.json"))]
        self.assertEqual(3, len(scenarios))
        self.assertEqual(len(scenarios), len({item.id for item in scenarios}))

    def test_rejects_free_form_executable_field_at_any_depth(self) -> None:
        raw = raw_scenario()
        raw["objective"]["shell"] = "not accepted"
        with self.assertRaisesRegex(ValidationError, "free-form executable field"):
            parse_scenario(raw)

    def test_rejects_unknown_top_level_field(self) -> None:
        raw = raw_scenario()
        raw["notes"] = "unsupported"
        with self.assertRaisesRegex(ValidationError, "unsupported fields"):
            parse_scenario(raw)

    def test_rejects_unknown_primitive(self) -> None:
        raw = raw_scenario()
        raw["constraints"]["allowed_primitives"][0] = "external.unbounded"
        with self.assertRaisesRegex(ValidationError, "unknown primitive"):
            parse_scenario(raw)

    def test_rejects_forbidden_capability_conflict(self) -> None:
        raw = raw_scenario()
        raw["constraints"]["forbidden_capabilities"].append("social_engineering")
        with self.assertRaisesRegex(ValidationError, "expose forbidden capabilities"):
            parse_scenario(raw)

    def test_rejects_unavailable_detection_event(self) -> None:
        raw = raw_scenario()
        raw["detection_criteria"][0]["ordered_event_types"][0] = "unavailable_event"
        with self.assertRaisesRegex(ValidationError, "event types unavailable"):
            parse_scenario(raw)

    def test_rejects_detection_count_larger_than_sequence(self) -> None:
        raw = raw_scenario()
        raw["detection_criteria"][0]["minimum_matching_events"] = 99
        with self.assertRaisesRegex(ValidationError, "cannot exceed"):
            parse_scenario(raw)

    def test_rejects_mistyped_expected_result(self) -> None:
        raw = raw_scenario()
        raw["expected_results"][1]["value"] = "six"
        with self.assertRaisesRegex(ValidationError, "must be an integer"):
            parse_scenario(raw)

    def test_rejects_impossible_expected_source(self) -> None:
        raw = raw_scenario()
        raw["expected_results"][3]["value"] = "unavailable_source"
        with self.assertRaisesRegex(ValidationError, "cannot be emitted"):
            parse_scenario(raw)

    def test_rejects_unsupported_schema_version(self) -> None:
        raw = raw_scenario()
        raw["schema_version"] = "9.9"
        with self.assertRaisesRegex(ValidationError, "unsupported schema version"):
            parse_scenario(raw)

    def test_rejects_naive_timestamp(self) -> None:
        raw = raw_scenario()
        raw["start_time"] = "2026-07-12T09:30:00"
        with self.assertRaisesRegex(ValidationError, "include a timezone"):
            parse_scenario(raw)

    def test_rejects_target_absent_from_topology(self) -> None:
        raw = raw_scenario()
        raw["topology"]["required_roles"] = []
        with self.assertRaisesRegex(ValidationError, "objective target role"):
            parse_scenario(raw)

    def test_input_is_not_mutated(self) -> None:
        raw = raw_scenario()
        before = copy.deepcopy(raw)
        parse_scenario(raw)
        self.assertEqual(before, raw)


if __name__ == "__main__":
    unittest.main()
