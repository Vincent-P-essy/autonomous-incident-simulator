# Scenario DSL 1.0

The machine-readable structural contract is
[`schemas/scenario-v1.schema.json`](../schemas/scenario-v1.schema.json). The DSL is
JSON so that parsing behavior is unambiguous and no object constructors or tags can
be embedded in input.

## Top-level contract

| Field | Purpose |
|---|---|
| `schema_version` | Exact compatibility boundary; currently `1.0` |
| `id`, `title`, `description` | Stable identity and inert presentation data |
| `seed` | Deterministic topology, ordering, duration, and identifiers |
| `start_time` | Timezone-aware fixed start for generated telemetry |
| `objective` | Supported objective kind and target asset role |
| `constraints` | Hard plan, technique, source, and capability boundaries |
| `topology` | Named profile, additional roles, synthetic user count |
| `detection_criteria` | Ordered observable event contracts |
| `expected_results` | Machine-evaluated scenario outcomes |
| `analyst_questions` | Training prompts with explicit evidence hints |

Unknown fields are errors, including fields nested inside any object.

## Constraint semantics

`allowed_primitives` is a positive allowlist. It is not a suggestion: the planner
cannot see other catalog entries. `forbidden_capabilities` is then intersected with
the capabilities of every allowed primitive. A conflict rejects the scenario
before planning.

`required_techniques`, `min_techniques`, `required_telemetry_sources`,
`max_steps`, and `max_duration_seconds` are all part of the goal test. The planner
does not return partial plans.

## Detection semantics

A criterion declares:

- event types that must occur in order;
- sources that must be represented by those matched events;
- a maximum first-to-last time span;
- a minimum matched-event count.

This is deliberately smaller than a full detection-rule language. The criteria
define ground-truth expectations for an exercise; they do not replace Sigma, a
SIEM query language, or production tuning.

## Evolution

Breaking field or semantic changes require a new schema version and parser path.
Existing golden scenarios must remain reproducible under their declared version.
New primitives require catalog tests, telemetry, capability labels, and an ATT&CK
mapping review.
