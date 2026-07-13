# Threat model

## Protected properties

- The host must not execute an action described by scenario input.
- The engine must not contact a target or external service.
- Unknown or contradictory input must fail closed.
- A report must not silently omit declared constraints.
- The same accepted scenario and engine version must produce the same report.
- The dashboard must not interpret scenario text as markup or executable content.

## Trust boundaries

1. Scenario JSON entering the parser is untrusted.
2. Catalog source code is trusted only after review and tests.
3. Output paths are trusted operator input to the CLI exporter.
4. HTTP clients are untrusted; the local API is not an authentication boundary.
5. Committed golden files are evidence, not truth, until regeneration succeeds.

## Abuse cases and controls

| Abuse case | Control |
|---|---|
| Inject an operating-system instruction into the DSL | Exact-key parsing, recursive executable-field rejection, no execution adapter |
| Reference a primitive outside the approved set | Positive allowlist plus catalog membership validation |
| Hide a dangerous capability inside an allowed primitive | Explicit capability labels and conflict rejection |
| Force planner to ignore time or coverage constraints | Complete goal predicate; failure if no valid node exists |
| Trigger a real connection through a topology address | No network client in the core; documentation-only ranges |
| Inject script or markup into the dashboard | Strict content security policy and DOM `textContent` rendering |
| Exhaust the API with a very large body | One-megabyte request limit; container memory and process limits |
| Tamper with committed evidence | Canonical regeneration and SHA-256 checks in CI |
| Add runtime behavior through a dependency | No third-party runtime dependency or plugin loader |

## Residual risks

- A malicious source-code change to the trusted catalog could violate assumptions;
  code review and CI reduce but do not eliminate this risk.
- The local API has no authentication or rate limiting. Loopback binding and a
  trusted reverse proxy are required boundaries.
- Resource exhaustion remains possible within accepted size limits under high
  concurrency; this service is a demonstrator, not a multi-tenant control plane.
- ATT&CK mappings can become stale or be contextually debatable.
- Export paths can overwrite files chosen by the same local operator.

## Safety invariants tested

- external side effects are false;
- process execution is false;
- real network activity is false;
- arbitrary actions are not accepted;
- every step resolves to the closed catalog;
- no forbidden capability occurs in a completed plan.
