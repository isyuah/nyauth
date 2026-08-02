# Nyauth Project Rules

## Security-Critical Vocabularies

- Security-sensitive operation identifiers must have one authoritative, domain-owned catalog. Do not maintain separate string allowlists in handlers, limiters, policy evaluation, telemetry, or tests.
- Rate-limit operations must use the sealed descriptors in `internal/securityaction`. Redis bucket names and metric labels must be derived from the same descriptor; handlers must not pass ad hoc action strings.
- Human-verification operations must use `humanverification.Action`. Parse external strings once at the HTTP or provider boundary, then keep the typed action through policy evaluation, verification, and telemetry.
- Adding an operation requires updating its catalog and contract tests in the same change. Unknown or zero-value operations must fail closed before creating Redis keys or bypassing a protection policy.
- Keep low-cardinality metric labels derived from bounded descriptors. Do not duplicate a second telemetry allowlist for an already bounded operation type.

## Dependency Fidelity

- A Redis emulator is not proof that Lua scripts behave like deployed Redis. Changes involving Lua JSON mutation, response types, TTL, or atomic consumption require a focused test against real Redis in addition to unit tests.
- Store application-generated structured payloads as opaque bytes when Lua only needs to perform compare-and-swap checks; do not decode and re-encode large integer fields in Redis Lua without a proven compatibility requirement.
