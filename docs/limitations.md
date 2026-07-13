# Limitations and roadmap

## Current limitations

- The topology is an abstract graph, not deployed infrastructure.
- Events are synthetic templates, not recordings from production sensors.
- Identity, network, endpoint, and application semantics are intentionally small.
- The planner handles monotonic facts and uses each primitive at most once; it does
  not model probabilistic failure, revocation, concurrent actors, or defensive
  state changes.
- ATT&CK identifiers are curated metadata rather than an automatically synchronized
  official knowledge-base snapshot.
- Detection criteria measure expected sequences, not precision or false positives
  on benign background traffic.
- The STIX-inspired export contains custom fields and is explicitly not a validated
  STIX 2.1 bundle.
- API authorization, persistence, multi-tenancy, quotas, and distributed execution
  are outside this vertical slice.
- The container base is pinned by digest, but a complete signed image provenance
  and automated digest-refresh policy remain future supply-chain work.
- Local latency depends on hardware, operating system, Python build, and load.

## Next evidence-bearing increments

1. Add licensed benign background datasets and compute precision, recall, and
   false-positive rates for exported detection rules.
2. Add schema migration tests and signed scenario manifests.
3. Import a pinned ATT&CK data snapshot with automated mapping validation.
4. Add defensive state transitions so isolation or credential revocation can alter
   a running pure simulation.
5. Compare abstract results with an independently isolated container lab while
   keeping the safe DSL as the only orchestrator input.
6. Add OpenTelemetry-compatible traces and adapters for detection-as-code tooling.
7. Produce a signed software bill of materials and pinned container digest.
