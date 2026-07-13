from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Tuple

from incident_simulator.api import create_server

from .helpers import EXAMPLES, raw_scenario


@contextmanager
def running_server() -> Iterator[Tuple[str, Any]]:
    server = create_server("127.0.0.1", 0, EXAMPLES)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def read_json(url: str) -> Tuple[int, Dict[str, Any], Any]:
    with urllib.request.urlopen(url, timeout=3) as response:
        return response.status, json.load(response), response.headers


class ApiTests(unittest.TestCase):
    def test_health_catalog_scenario_index_and_dashboard(self) -> None:
        with running_server() as (base, _):
            status, health, headers = read_json(base + "/api/v1/health")
            self.assertEqual(200, status)
            self.assertEqual("pure-simulation", health["execution_mode"])
            self.assertEqual("nosniff", headers["X-Content-Type-Options"])
            _, catalog, _ = read_json(base + "/api/v1/catalog")
            self.assertGreaterEqual(catalog["count"], 10)
            _, index, _ = read_json(base + "/api/v1/scenarios")
            self.assertEqual(3, len(index["scenarios"]))
            with urllib.request.urlopen(base + "/", timeout=3) as response:
                html = response.read().decode("utf-8")
                self.assertIn("Incident Simulation Control Room", html)
                self.assertIn(
                    "default-src 'self'", response.headers["Content-Security-Policy"]
                )

    def test_simulate_endpoint_returns_deterministic_report(self) -> None:
        raw = json.dumps(raw_scenario()).encode("utf-8")
        with running_server() as (base, _):
            request = urllib.request.Request(
                base + "/api/v1/simulate",
                data=raw,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=3) as response:
                payload = json.load(response)
            self.assertEqual("payroll-no-malware", payload["report"]["scenario"]["id"])
            self.assertEqual(
                1.0, payload["report"]["metrics"]["expected_result_pass_rate"]
            )
            self.assertEqual(64, len(payload["report_sha256"]))

    def test_simulate_endpoint_rejects_free_form_field(self) -> None:
        raw = raw_scenario()
        raw["objective"]["command"] = "rejected"
        with running_server() as (base, _):
            request = urllib.request.Request(
                base + "/api/v1/simulate",
                data=json.dumps(raw).encode("utf-8"),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as captured:
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(422, captured.exception.code)
            error = json.loads(captured.exception.read().decode("utf-8"))
            self.assertEqual("invalid_scenario", error["error"])


if __name__ == "__main__":
    unittest.main()
