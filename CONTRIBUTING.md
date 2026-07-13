# Contributing

## Design contract

Changes must preserve the core invariant: untrusted scenario text is data, never
behavior. New scenarios should compose existing catalog identifiers. New primitive
behavior belongs in reviewed source code and must include bounded durations,
capability labels, state preconditions/effects, inert telemetry, and mapping tests.

## Development workflow

```bash
export PYTHONPATH=src
python3 -m pip install -r requirements-build.lock -r requirements-dev.lock
make test
make quality
```

A pull request should explain the threat-model impact, include positive and
negative tests, and update golden evidence only when deterministic output changes
intentionally. Never update a golden hash without inspecting the corresponding
report diff.

## Scenario checklist

- Version and seed are explicit.
- Objective target exists in the generated topology.
- Allowed primitives are minimal.
- Dangerous and irrelevant capabilities are forbidden.
- Duration, steps, techniques, and telemetry sources are constrained.
- At least one ordered multi-source detection criterion is present.
- Expected results and analyst questions reference observable evidence.
- `scripts/quality_gate.py` passes twice-identical output checks.

## Code style

Use typed immutable models at trust boundaries, deterministic ordering, standard
library facilities where practical, explicit errors, and tests for failure paths.
Do not depend on process-global hash ordering or wall-clock time for report content.

## Commit hygiene

Keep commits focused and authored with your own verified Git identity. Do not add
automated co-author trailers. No generated cache, local output directory, secret,
or personal dataset belongs in version control.
