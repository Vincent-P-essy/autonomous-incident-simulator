from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from .helpers import EXAMPLES, ROOT


class CliEndToEndTests(unittest.TestCase):
    def _run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "incident_simulator", *arguments],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )

    def test_validate_and_export_workflow(self) -> None:
        scenario = str(EXAMPLES / "payroll-no-malware.json")
        validation = self._run("validate", scenario)
        self.assertEqual(0, validation.returncode, validation.stderr)
        self.assertTrue(json.loads(validation.stdout)["valid"])
        with tempfile.TemporaryDirectory() as directory:
            result = self._run("simulate", scenario, "--output-dir", directory)
            self.assertEqual(0, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(5, len(payload["artifacts"]))
            self.assertTrue(
                all(Path(path).exists() for path in payload["artifacts"].values())
            )

    def test_invalid_scenario_has_structured_error_and_nonzero_exit(self) -> None:
        result = self._run("validate", str(ROOT / "missing.json"))
        self.assertEqual(2, result.returncode)
        error = json.loads(result.stderr)
        self.assertEqual("ValidationError", error["error"])


if __name__ == "__main__":
    unittest.main()
