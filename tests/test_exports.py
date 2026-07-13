from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from incident_simulator.dsl import load_scenario
from incident_simulator.exporters import (
    stix_like_bundle,
    telemetry_jsonl,
    write_artifacts,
)
from incident_simulator.serialization import digest
from incident_simulator.simulator import simulate

from .helpers import EXAMPLES, ROOT


class ExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = simulate(load_scenario(EXAMPLES / "payroll-no-malware.json"))

    def test_jsonl_has_one_valid_record_per_event(self) -> None:
        lines = telemetry_jsonl(self.report).splitlines()
        self.assertEqual(len(self.report["telemetry"]), len(lines))
        self.assertEqual(self.report["telemetry"], [json.loads(line) for line in lines])

    def test_stix_like_export_is_deterministic_and_explicitly_nonconformant(
        self,
    ) -> None:
        first = stix_like_bundle(self.report)
        second = stix_like_bundle(self.report)
        self.assertEqual(first, second)
        self.assertEqual("bundle", first["type"])
        self.assertEqual("2.1-inspired", first["spec_version"])
        self.assertIn("not validated", first["x_conformance"])
        self.assertTrue(
            any(item["type"] == "attack-pattern" for item in first["objects"])
        )

    def test_artifact_writer_produces_complete_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = write_artifacts(self.report, Path(directory))
            self.assertEqual(
                {"report", "telemetry", "ground_truth", "stix_like", "summary"},
                set(paths),
            )
            self.assertTrue(all(Path(path).is_file() for path in paths.values()))
            exported = json.loads(Path(paths["report"]).read_text(encoding="utf-8"))
            self.assertEqual(digest(self.report), digest(exported))

    def test_committed_golden_manifest_matches_report(self) -> None:
        manifest_path = (
            ROOT / "datasets" / "golden" / "payroll-no-malware" / "manifest.json"
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(digest(self.report), manifest["report_sha256"])
        self.assertEqual(len(self.report["telemetry"]), manifest["event_count"])
        self.assertEqual(
            self.report["metrics"]["technique_count"], manifest["technique_count"]
        )


if __name__ == "__main__":
    unittest.main()
