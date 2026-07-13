"""Command-line interface for validation, simulation, export, and serving."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .api import serve
from .catalog import all_primitives
from .dsl import load_scenario
from .errors import IncidentSimulatorError
from .exporters import write_artifacts
from .metrics import benchmark
from .models import to_jsonable
from .planner import build_plan
from .serialization import digest, pretty_json
from .simulator import simulate
from .topology import generate_topology


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="incident-sim",
        description="Deterministic, catalog-only cyber-incident simulator",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    validate = subparsers.add_parser(
        "validate", help="validate a scenario and prove that a safe plan exists"
    )
    validate.add_argument("scenario", type=Path)

    plan = subparsers.add_parser(
        "plan", help="print the generated topology and safe plan"
    )
    plan.add_argument("scenario", type=Path)

    run = subparsers.add_parser("simulate", help="run a pure simulation")
    run.add_argument("scenario", type=Path)
    run.add_argument("--output-dir", type=Path)
    run.add_argument(
        "--full",
        action="store_true",
        help="print the complete report instead of a concise summary",
    )

    bench = subparsers.add_parser(
        "benchmark", help="measure determinism, latency, and coverage"
    )
    bench.add_argument("scenario", type=Path)
    bench.add_argument("--runs", type=int, default=20)
    bench.add_argument("--output", type=Path)

    subparsers.add_parser("catalog", help="print all allowlisted primitives")

    server = subparsers.add_parser("serve", help="serve the local API and dashboard")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=int, default=8080)
    server.add_argument("--scenario-dir", type=Path, default=Path("examples"))
    return parser


def _execute(args: argparse.Namespace) -> int:
    if args.subcommand == "catalog":
        print(
            pretty_json(
                {"primitives": [to_jsonable(item) for item in all_primitives()]}
            ),
            end="",
        )
        return 0
    if args.subcommand == "serve":
        if not 1 <= args.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        serve(args.host, args.port, args.scenario_dir)
        return 0

    spec = load_scenario(args.scenario)
    topology = generate_topology(spec.topology, spec.seed)
    plan = build_plan(spec, topology)
    if args.subcommand == "validate":
        print(
            pretty_json(
                {
                    "valid": True,
                    "scenario_id": spec.id,
                    "schema_version": spec.schema_version,
                    "plan_steps": len(plan.steps),
                    "duration_seconds": plan.total_duration_seconds,
                    "techniques": sorted({step.technique_id for step in plan.steps}),
                    "safety": "catalog-only",
                }
            ),
            end="",
        )
        return 0
    if args.subcommand == "plan":
        print(pretty_json({"topology": topology, "plan": plan}), end="")
        return 0
    if args.subcommand == "simulate":
        report = simulate(spec, topology, plan)
        files = write_artifacts(report, args.output_dir) if args.output_dir else {}
        if args.full:
            print(pretty_json(report), end="")
        else:
            print(
                pretty_json(
                    {
                        "scenario_id": spec.id,
                        "report_sha256": digest(report),
                        "metrics": report["metrics"],
                        "safety": report["safety"],
                        "artifacts": files,
                    }
                ),
                end="",
            )
        return 0
    if args.subcommand == "benchmark":
        result = benchmark(spec, runs=args.runs)
        rendered = pretty_json(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
        return 0
    raise AssertionError("unreachable subcommand")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return _execute(args)
    except (IncidentSimulatorError, ValueError) as exc:
        print(
            json.dumps(
                {"error": type(exc).__name__, "detail": str(exc)}, sort_keys=True
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
