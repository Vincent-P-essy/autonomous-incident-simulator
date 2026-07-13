# Experimental methodology

## Research questions

The current experiment asks:

1. Can a constrained planner always produce the same explainable sequence for the
   same approved scenario and seed?
2. Does each sequence emit enough multi-source evidence to satisfy its declared
   detection contract?
3. Can safety constraints be enforced structurally instead of inferred from free
   text?
4. What is the local computational cost of planning, simulation, and evaluation?

## Procedure

For each scenario, the quality gate:

1. parses and semantically validates the DSL;
2. creates the seeded topology;
3. finds a complete plan or fails closed;
4. simulates twice independently;
5. compares canonical SHA-256 digests;
6. verifies objective, technique, source, duration, detection, and safety measures.

The flagship benchmark repeats the full pipeline 50 times in one process and
records minimum, median, p95, and maximum wall-clock latency. Output latency is
reported separately from deterministic report data.

## Measures

| Measure | Definition |
|---|---|
| Determinism | Number of distinct canonical report digests across repeated runs |
| Technique coverage | Required technique identifiers observed / required identifiers |
| Source coverage | Required telemetry sources observed / required sources |
| Detection pass rate | Matched declared detection criteria / all criteria |
| Expected-result pass rate | Passed assertions / all assertions |
| Engine latency | Wall time for topology, planning, simulation, and evaluation |

## Golden dataset

The committed flagship bundle contains the input scenario, full report, JSONL
events, ground truth, STIX-inspired view, Markdown summary, benchmark, manifest,
and independent file hashes. CI regenerates the canonical report and rejects
drift. Benchmark latency is retained as experimental evidence but is not used as a
cross-platform pass threshold.

## Interpretation

A passed criterion proves that the synthetic generator honored its own declared
contract. It does not prove that a real sensor would capture the same evidence or
that a production detection has acceptable false-positive behavior. That requires
replay against real, appropriately licensed telemetry and a separate evaluation
design.
