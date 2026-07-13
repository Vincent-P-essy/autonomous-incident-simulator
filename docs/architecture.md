# Architecture

## Design goals

The engine optimizes for four properties: safety by construction, reproducibility,
inspectable causality, and measurable output. It intentionally trades away the
expressiveness of free-form instructions.

## Layers

### 1. DSL boundary

`dsl.py` treats every scenario as untrusted. It performs:

1. recursive rejection of executable-style field names;
2. exact-key validation at every object boundary;
3. primitive, topology, event, source, and technique reference checks;
4. capability-conflict and constraint-feasibility checks;
5. conversion to frozen typed models.

The JSON Schema is useful for editors and pre-validation. The Python semantic
validator is authoritative because JSON Schema alone cannot prove that a required
source can be emitted by an allowed primitive.

### 2. Closed primitive catalog

Each primitive contains only:

- an identifier and human title;
- curated ATT&CK metadata;
- required and produced abstract facts;
- capability labels;
- a bounded duration interval;
- inert telemetry templates.

There is no callback field or extension mechanism. Adding behavior requires a
reviewed source-code change and tests.

### 3. Generated topology

The generator expands a named profile plus required roles into immutable assets,
identities, and allowed-flow metadata. Stable SHA-256-derived identifiers make the
same seed repeatable. All addresses come from RFC documentation ranges and are
never contacted.

### 4. Planner

The planner performs breadth-first search over sets of abstract facts. Candidate
ordering and duration choices are derived from SHA-256 of the seed and stable
identifiers; Python's process-randomized hash is never used.

A node is accepted only when all of the following hold:

- the objective fact exists;
- every required technique is represented;
- the minimum distinct-technique count is met;
- every required telemetry source can be observed;
- the maximum step and duration limits are respected.

If no node satisfies the complete contract, planning fails. It never relaxes a
constraint or substitutes an unknown primitive.

### 5. Pure simulator

The simulator transforms a plan into timestamped events. It uses fixed input time,
seed-derived identifiers, bounded seeded durations, and template-relative event
offsets. It does not read mutable system state. The report is therefore identical
for identical scenario bytes after parsing.

### 6. Evaluation and exports

Detection criteria evaluate ordered event sequences, source diversity, event
count, and time windows. Expected-result assertions cover objective completion,
technique depth, duration, source presence, and absent capabilities.

Export code is the only layer that writes files, and only to a path explicitly
chosen by the CLI caller. The simulation core returns ordinary immutable models
and JSON-compatible dictionaries.

### 7. Interfaces

The CLI validates, plans, simulates, benchmarks, exports, and serves. The HTTP API
accepts the same DSL and calls the same parser and engine. The dashboard contains
no alternate simulation logic and renders untrusted text through DOM `textContent`.

## Determinism boundary

Included in deterministic output:

- topology and identifiers;
- plan order and durations;
- timestamps and telemetry;
- ground truth and all evaluations;
- report metrics based on simulated data.

Excluded from deterministic output:

- wall-clock benchmark latency;
- filesystem paths selected for export;
- HTTP transport metadata.

The canonical report digest sorts object keys and uses compact UTF-8 JSON. Golden
verification regenerates the report rather than trusting the committed copy.

## Dependency boundary

The engine, API, dashboard, scripts, and tests use no third-party runtime package.
Setuptools is needed only to build/install the optional package and is exactly
pinned in `requirements-build.lock`.
