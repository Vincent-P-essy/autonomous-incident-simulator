"""Small dependency-free HTTP API and dashboard server."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Type
from urllib.parse import unquote, urlparse

from . import __version__
from .catalog import all_primitives
from .dsl import load_scenario, parse_scenario
from .errors import IncidentSimulatorError
from .models import to_jsonable
from .serialization import digest
from .simulator import simulate


MAX_REQUEST_BYTES = 1_048_576
_WEB_DIR = Path(__file__).with_name("web")


def _scenario_files(scenario_dir: Path) -> List[Path]:
    return sorted(path for path in scenario_dir.glob("*.json") if path.is_file())


def _scenario_index(scenario_dir: Path) -> List[Dict[str, Any]]:
    result = []
    for path in _scenario_files(scenario_dir):
        scenario = load_scenario(path)
        result.append(
            {
                "id": scenario.id,
                "title": scenario.title,
                "description": scenario.description,
                "seed": scenario.seed,
                "objective": to_jsonable(scenario.objective),
            }
        )
    return result


def _find_scenario(scenario_dir: Path, scenario_id: str) -> Any:
    for path in _scenario_files(scenario_dir):
        scenario = load_scenario(path)
        if scenario.id == scenario_id:
            return scenario
    raise FileNotFoundError(scenario_id)


def handler_for(scenario_dir: Path) -> Type[BaseHTTPRequestHandler]:
    configured_dir = scenario_dir.resolve()

    class Handler(BaseHTTPRequestHandler):
        server_version = "IncidentSimulator/0.1"

        def log_message(self, format: str, *args: object) -> None:
            # Keep structured API output clean; operators may wrap the process with
            # their preferred access logger.
            return

        def _headers(
            self, status: int, content_type: str, length: int, cache: str = "no-store"
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", cache)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                "img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            )
            self.end_headers()

        def _json(self, status: int, value: Any) -> None:
            body = (
                json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n"
            ).encode("utf-8")
            self._headers(status, "application/json; charset=utf-8", len(body))
            self.wfile.write(body)

        def _file(self, path: Path, content_type: str) -> None:
            try:
                body = path.read_bytes()
            except FileNotFoundError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "asset_not_found"})
                return
            self._headers(
                HTTPStatus.OK, content_type, len(body), cache="public, max-age=300"
            )
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
            path = unquote(urlparse(self.path).path)
            try:
                if path == "/":
                    self._file(_WEB_DIR / "index.html", "text/html; charset=utf-8")
                elif path == "/assets/app.js":
                    self._file(_WEB_DIR / "app.js", "text/javascript; charset=utf-8")
                elif path == "/assets/styles.css":
                    self._file(_WEB_DIR / "styles.css", "text/css; charset=utf-8")
                elif path == "/api/v1/health":
                    self._json(
                        HTTPStatus.OK,
                        {
                            "status": "ok",
                            "engine_version": __version__,
                            "execution_mode": "pure-simulation",
                        },
                    )
                elif path == "/api/v1/catalog":
                    self._json(
                        HTTPStatus.OK,
                        {
                            "count": len(all_primitives()),
                            "primitives": [
                                to_jsonable(item) for item in all_primitives()
                            ],
                        },
                    )
                elif path == "/api/v1/scenarios":
                    self._json(
                        HTTPStatus.OK, {"scenarios": _scenario_index(configured_dir)}
                    )
                elif path.startswith("/api/v1/scenarios/"):
                    scenario_id = path.removeprefix("/api/v1/scenarios/")
                    scenario = _find_scenario(configured_dir, scenario_id)
                    self._json(HTTPStatus.OK, to_jsonable(scenario))
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            except FileNotFoundError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "scenario_not_found"})
            except IncidentSimulatorError as exc:
                self._json(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    {"error": "invalid_scenario", "detail": str(exc)},
                )

        def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
            path = unquote(urlparse(self.path).path)
            if path != "/api/v1/simulate":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            content_type = self.headers.get_content_type()
            if content_type != "application/json":
                self._json(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    {"error": "application_json_required"},
                )
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_content_length"})
                return
            if content_length <= 0 or content_length > MAX_REQUEST_BYTES:
                self._json(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    {"error": "request_size_rejected"},
                )
                return
            try:
                raw = json.loads(self.rfile.read(content_length).decode("utf-8"))
                report = simulate(parse_scenario(raw))
                self._json(
                    HTTPStatus.OK,
                    {"report_sha256": digest(report), "report": report},
                )
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            except IncidentSimulatorError as exc:
                self._json(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    {"error": "invalid_scenario", "detail": str(exc)},
                )

    return Handler


def create_server(host: str, port: int, scenario_dir: Path) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), handler_for(scenario_dir))
    server.daemon_threads = True
    return server


def serve(host: str, port: int, scenario_dir: Path) -> None:
    server = create_server(host, port, scenario_dir)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
