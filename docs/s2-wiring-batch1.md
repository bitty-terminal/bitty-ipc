# S2 transport-wiring readiness, Batch 1 (mechanical)

Scope: wiring items 2, 3, 4, 5, 6, 8 from the review verdict on
`bitty-terminal/bitty-ipc#21` (COMPATIBLE, no envelope reshape). Batch 2
(method names plus required scopes plus per-op consent gating; items 1 and 7)
is a separate later task and is NOT decided here.

Normative base: `bitty-ai-docs` `specifications/ipc-agent-rfc.md` (accepted
2026-08-29; normative on conflict). Every normative-sounding statement below
cites that RFC or is marked `CANDIDATE (CTX-0005)` for security/architecture
reviewer confirmation. The batch-1 `CANDIDATE (CTX-0005)` marks are all
resolved under CTX-0012 (now marked `POLICY (CTX-0012)` confirmed/decided,
none open). S2 shape citations refer to `bitty-ai @ a11bad7`,
`crates/bitty-ai-host/src/`, read-only reference; no `bitty-ai` crate is
depended on (dependency direction stays one-way: `bitty-ai` consumes
`bitty-ipc-api`, never the reverse).

Out of scope here (open, pointed at Batch 2): wire method-name strings for AI
domain ops, required-scope registry entries for those ops, and per-op consent
policy. The method registry (`scope.rs`: 38 wire-stable methods) is
unchanged by this batch.

## Item 2 — Canonical params/result JSON mapping

S2 domain shapes define no `v`/`id`/`method` and no framing of their own;
they ride inside `params`/`result` under the wire envelope (RFC §Wire
protocol, "Envelope"). Canonical rules, in validation order:

1. Envelope first: `v`, `id`, `method` validate per `wire.rs` before any
   `params`/`result` byte is interpreted (RFC §Wire protocol, envelope rules).
2. Frame bound: `params`/`result` bytes are `<= 256 KiB` (`MAX_FRAME_BYTES`;
   RFC §Transport and bounded framing).
3. UTF-8: bytes must be valid UTF-8 JSON; non-UTF-8 is refused whole with
   `InvalidFrame` before any parse (RFC §Failure semantics, FS-IP7).
4. Depth: object-graph nesting is at most 32 deep (`MAX_JSON_DEPTH`; RFC §Wire
   protocol, envelope rules; T-01 stack-exhaustion defense).
5. No ambient authority: top-level `auth`/`scope`/`role` keys are refused;
   the server ignores such fields and evaluates the caller's real scope
   (RFC §Wire protocol, envelope rules; RFC §Authorization and scopes).
6. Strings bounded in bytes, not characters: every S2 string field that
   crosses must fit its IPC-side byte bound; multi-byte UTF-8 counts every
   byte. Grammar checks (name shapes) stay S2-owned; the IPC side enforces
   bytes plus UTF-8 only.
7. Schema validation is one layer above: the channel treats `params` as
   opaque bytes, and per-op field schemas ride with the method registry in
   Batch 2. Unknown non-authority fields inside `params` pass through
   opaquely.

Executable form: `ipc-api/src/json.rs` (`validate_params_json`,
`validate_result_json`); UTF-8 plus depth-`<= 32` confirmation tests live
there. Per-method `params`/`result` field schemas ride one layer above in
`ipc-api/src/schema.rs` (`validate_ai_params`, `validate_ai_result`;
CTX-0011): closed `check_known` vocabularies — unknown fields refuse with
`InvalidRequest`, never pass through.

### S-1 snapshot correlator allowance (CTX-0014)

The S-C per-method `params` schemas allow-list one optional `u64` field
`snapshot_version` on all 13 `ai.*` methods (absent = S-2 fallback; the
existing `opt()` absent-means-default machinery, no required/optional
flip for any other field). Shape parity with the `bitty-ai` endpoint E2
contract: full `u64` range accepted, non-`u64` types refuse
`InvalidRequest`, duplicates refuse through the existing schema
duplicate-key rule, unknown OTHER fields still refuse. No enforcement
change on either side (the endpoint stays tolerant until S-F; AI-0303
tracks the enforcement flip).

Follow-up (separate `bitty-ai` task): the endpoint tripwire test
(`gate5_refuses_correlator_pending_schema_allowance`) fails loudly now
that the allowance has landed — update it to the allowed path
(dispatch-path disposition coverage) instead of deleting it — plus the
`bitty-ipc-api` pin bump.

### IPC-side string byte bounds (currently-unbounded S2 strings)

| S2 field (unbounded today)                                                                                                                                            | IPC-side bound                                                                                                                                                                                                                                          | Precedent                                                                                               |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Selection alias (`SelectEnvelopeRequest.alias`; no validation at construction, `model_selection.rs`)                                                                  | `MAX_AGENT_ALIAS_BYTES = 128` // POLICY (CTX-0012): CONFIRMED — smallest bound consistent with the S2 name precedent; changing the value needs an RFC revision (item 8). The executable `CANDIDATE` marks in `json.rs` flip under CTX-0011.             | S2 `MAX_MODEL_NAME_LEN` (`128`, same-shape routing-name precedent, `provider_registry.rs`)              |
| `Manifest` strings (`name`, `version`, opaque `host` predicate) and the eight point-descriptor strings ("opaque string only; no validation", `extension_registry.rs`) | `MAX_MANIFEST_FIELD_BYTES = 512` // POLICY (CTX-0012): CONFIRMED — smallest bound consistent with the S2 opaque-string precedent; changing the value needs an RFC revision (item 8). The executable `CANDIDATE` marks in `json.rs` flip under CTX-0011. | S2 `MAX_TOOL_DESCRIPTION_LEN` (`512`, owner-supplied opaque short-string precedent, `tool_dispatch.rs`) |

Both bounds are recommendations: S2 imposes none, so reviewer confirmation is
needed before transport scoping enforces them. Enforcement shape is
`LimitExceeded { field, limit, actual }` (the established count/length
pattern, as for `method`/`id` length checks).

## Item 3 — Per-op-class size disposition

Caps: `256 KiB` per frame (RFC §Transport and bounded framing) and `1 MiB`
logical per request (RC-9; RFC §Rate limits and budgets: a logical request
that would exceed `1 MiB` must be chunked client-side; excess is rejected
whole with `Denied`/`PayloadCap`, FS-IP1). Chunking is RC-10 `chunk` frames
(`seq`/`total`, `<= 256 KiB` decoded each; RFC §Agent auth, consent, and
streaming). Executable form: `ipc-core/src/limits.rs` (`chunks_required`,
`check_payload_cap`) plus `wire.rs` (`validate_chunk`).

| Flagged case                                                                                                                                              | Worst case                                           | Disposition                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| --------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CompleteRequest` chain (`provider_registry.rs`: 128 messages x 16 KiB + 128 refs x 64 B + 32 tools x 64 B = 2,107,392 bytes before JSON overhead)        | ~2 MiB, past both the frame and the RC-9 logical cap | CHUNK via RC-10: the chain crosses as a `seq`/`total` chunk sequence (9 chunks at the cited worst case), never as one logical request past the RC-9 cap (RFC §Rate limits and budgets, RC-9 row). Tested in `limits.rs`.                                                                                                                                                                                                                                                                                         |
| `ContextReadResponse` count-only validation (`context_providers.rs`: `validate` checks counts only, records `<= 128`, absences `<= 64`)                   | Count-valid but byte-heavy response                  | TIGHTEN by layering: the S2 count checks are necessary, not sufficient. The wire layer additionally enforces the `256 KiB` frame bound, depth `<= 32`, and the `1 MiB` logical cap on the wire form, so a count-valid response can still be refused at the wire. No new S2 bound is requested. Tested via `validate_response_envelope` oversize refusal.                                                                                                                                                         |
| Unbounded select chain (`model_selection.rs`: `SelectEnvelopeResponse::Selected` carries a `Vec<SelectedModel>` chain with no envelope-level count bound) | Chain entries scale with registry size               | CHUNK plus TIGHTEN-candidate, POLICY (CTX-0012): DECIDED docs-only — no IPC-side enforcement. Chains enter IPC as opaque `params` bytes (item 2 rule 7), so no chain-entry validation point exists; parsing S2 shapes inside IPC would break the opaque-params layering, and silent enforcement would split responses the selection seam considers legal. The RC-10 chunk plan already carries any length. A bound needs a joint S2 + RFC revision (item 8); the TIGHTEN-candidate stays open for that revision. |

## Item 4 — S2-refusal to IpcError/Denied-code table

Executable form: `ipc-api/src/refusal.rs` (`AgentRefusal::to_ipc_error`,
total with no wildcard arm). No new `IpcError` variant is introduced; every
class maps onto the accepted RFC error taxonomy (RFC §Wire protocol, "Error
taxonomy"). Refusals carry counts and bounds only, never caller bytes.

| S2 refusal class                                                                              | IPC-side expression                                                                                                                                                                                                                                                             | Basis                                                                                                                                                                                                                          |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Unknown` / ack-loss (effect may have happened; reconcile before retry, never blind fallback) | `Unavailable` // POLICY (CTX-0012): CONFIRMED — the S2 `Unknown` fallback directive is "stop with reconcile", which `Unavailable` expresses; no `Unknown` variant exists, so no new variant is needed.                                                                          | Recommended over a new code: the RFC taxonomy already carries "service unavailable" with fail-closed reconcile semantics (RFC §Wire protocol, "Error taxonomy"); a new variant would need an RFC revision.                     |
| `ReservedScopeDenied` (list-style caller scope; MP-4 filtering deferred)                      | `Denied` / `ScopeViolation`                                                                                                                                                                                                                                                     | Scope posture denied, but the required-scope registry entries are Batch 2 (item 1), so no `ScopeDenied` scope string is assigned here; Batch 2 may refine to `ScopeDenied`.                                                    |
| `BudgetExceeded { limit, actual }`                                                            | `Denied` / `PayloadCap`                                                                                                                                                                                                                                                         | Accepted RC-9 expression for payload past cap, rejected whole (RFC §Rate limits and budgets, RC-9 row; FS-IP1).                                                                                                                |
| `TimeoutTooLarge { max, actual }`                                                             | `InvalidRequest`                                                                                                                                                                                                                                                                | Same shape the channel already enforces at construction (`IpcRequest::new` rejects `timeout_ms` of `0` or past the ceiling with `InvalidRequest`).                                                                             |
| `FallbackError::Malformed` (bad magic, short/overrunning framing, non-UTF-8, trailing bytes)  | `InvalidFrame`                                                                                                                                                                                                                                                                  | Nested domain codec failed inside `params`/`result`; the envelope reports the framing failure without further parse (RFC §Wire protocol, envelope rules).                                                                      |
| `CacheHintError::ScopeMismatch`, `KeyMismatch`                                                | `InvalidRequest` // POLICY (CTX-0012): CONFIRMED shape-not-authz — `Denied`/`ScopeViolation` would fabricate an authorization verdict where no grant decision runs.                                                                                                             | The S2 shape check is a pure equality gate with matching left to the caller, so the IPC expression is a shape refusal, not an authorization verdict; a reviewer could read `ScopeMismatch` as an authorization signal instead. |
| `ContextReadError::EmptyScopes`                                                               | `InvalidRequest`                                                                                                                                                                                                                                                                | Required field missing (FS-IP1 transactional denial).                                                                                                                                                                          |
| `ProviderError::Auth` (provider refused authorization; fallback `Stop`, never spray)          | `Denied` / `ProviderAuth` (new code) // POLICY (CTX-0012): DECIDED — never `Unauthenticated` (transport peer verdict), never `Unavailable` (invites retry/fallback).                                                                                                            | Gap closed here: static reason only, no provider id, no credential material crosses; `Denied` codes are strings, so no RFC revision is needed.                                                                                 |
| `ContextReadError::TooManyScopes` / `TooManyRecords` / `TooManyAbsences`                      | `LimitExceeded { field, limit, actual }` // POLICY (CTX-0012): CONFIRMED over `Denied`/`PayloadCap` — RC-9 `PayloadCap` covers a logical payload past the `1 MiB` cap rejected whole, not per-field count overruns; `LimitExceeded` reports `ErrorClass::Framing`, fail-closed. | Preserves the S2 `{limit, actual}` count pair exactly, matching the codebase pattern for count/length overruns; the alternative is `Denied` / `PayloadCap` (RC-9 language).                                                    |

Gap closed (CTX-0012, decided, not silently chosen): the S2 provider-authorization
refusal (`ProviderError::Auth`: provider refused authorization, fallback
directive `Stop` — reconcile credentials, never spray) maps to `Denied` with
new code `ProviderAuth` (executable form: `AgentRefusal::ProviderAuthDenied`).
It must NOT map to `Unauthenticated` (that class is the transport
peer-credential verdict, RFC §Authentication: conflating a downstream
provider-credential refusal with a local peer-auth failure would misdirect
incident response and could mask a real transport-auth breach), nor to
`Unavailable` (which invites reconcile-then-retry and fallback, contradicting
the never-spray rule and risking account lockout). `Denied` codes are
open-ended strings, so the new code needs no RFC revision. The mapped error
carries a static reason only — no provider id, no credential material, no
provider-echoed text.

## Item 5 — Correlation binding and attribution rules

Layers, outermost to innermost (S2 domain shapes carry no `v`/`id`/`method`;
correlation rides the wire envelope, RFC §Wire protocol, "Envelope"):

1. Wire `id` (`<= 64` bytes) <-> channel `RequestId` (non-zero `u64`):
   the envelope carries the wire id as text; the channel tracks the numeric
   request. `WireBinding` (`ipc-api/src/correlation.rs`) validates both ends
   and matches responses; correlation never reuses an id under pressure
   (pending-table discipline, `IpcEndpoint::complete`). Tested, including
   end-to-end through the endpoint with no channel-routing change.
2. `RequestId` <-> domain attribution handles: S2 `AuthBase` carries
   `(agent_instance_id, session_id)` plus the server-side tier, and S2
   `ExecutionContext` carries `(execution_id, now_ms)` as a transient
   dispatch identity. `AttributionHandles` mirrors the three `u64` handles
   with redacted `Debug` (tested: no handle digits emitted).
3. Argument binding: S2 `DispatchRequest` crosses digest-only (FNV-1a-64 over
   the raw argument bytes); the transport binds its own argument bytes to
   that digest out-of-band (`args_digest` / `verify_args_digest`, same
   FNV-1a-64 parameters as the S2 `UsageEvent::args_digest` precedent, pinned
   by standard test vectors; mismatch fails closed).

Transport-wiring obligations (not code): re-derive tier and grants
server-side from the authenticated identity on every request (`AuthBase` and
caller-scope echoes are transport-enforced inputs and observation, never
grants; RFC §Authorization and scopes); treat handles as attribution-only;
never store and never log the domain `ExecutionContext` (S2
`tool_dispatch.rs`: transient by construction); never log raw argument bytes
(digest only). Per-op consent gating is Batch 2 (item 7) and stays open here.

## Item 6 — Timeout/deadline enforcement binding

Both ceilings are `30 s`: the S2 `CompleteRequest` early-refusal ceiling
(`MAX_REQUEST_TIMEOUT_MS`) and the channel construction ceiling
(`MAX_REQUEST_TIMEOUT_MS`) are the same bound (tested literal pin; changing
either side requires a joint revision, never silent drift). The transport
default is `5 s` (`DEFAULT_REQUEST_TIMEOUT_MS`) for callers that supply no
explicit deadline, still caller-`now_ms`-relative (RFC §Agent auth, consent,
and streaming: timeouts are "checked from caller-supplied `now_ms`, never
wall-clock time").

| Layer                                              | Rule                                                                      | Effect                            |
| -------------------------------------------------- | ------------------------------------------------------------------------- | --------------------------------- |
| S2 envelope (`CompleteRequest::check`)             | refuse `timeout_ms` past the ceiling early                                | `TimeoutTooLarge` before any work |
| S2 execution                                       | re-check the ceiling authoritatively at execution time                    | pre-I/O refusal, no partial state |
| IPC channel construction (`IpcRequest::new`)       | refuse `timeout_ms` of `0` or past the ceiling                            | `InvalidRequest`, never queued    |
| IPC channel reaping (`IpcEndpoint::drain_expired`) | drop expired ids from the pending table AND the not-yet-handed-over queue | no-exec-after-timeout (tested)    |
| Transport default                                  | `5 s` when the caller supplies no explicit deadline                       | deterministic default             |

Caller-`now_ms` mapping rule: the domain `now_ms` maps verbatim to channel
`created_at_ms`; the absolute deadline is `now_ms.saturating_add(timeout_ms)`;
expiry holds when `now >= deadline`. No wall-clock time is read at any step.
Executable form and tests: `ipc-api/src/deadline.rs`
(`validate_domain_timeout`, `domain_deadline_ms`, mapped-request
no-exec-after-timeout coverage).

## Item 8 — Versioning policy confirmation

Domain shapes ride wire `v`: S2 envelopes carry no version field of their own
(by S2 convention across `provider_registry.rs`, `model_selection.rs`,
`tool_dispatch.rs`, `context_providers.rs`, `extension_registry.rs`,
`cache_disclosure.rs`, `mcp_placement.rs`), and versioning/negotiation stays
with the wire envelope (`v`, `SUPPORTED_WIRE_VERSIONS`,
`negotiate_wire_version` in `wire.rs`; RFC §Wire protocol, "Versioning": the
runtime advertises its wire version in the discovery file and the `hello`
response; a future wire version stays backward-readable for at least one
major version).

Extension rule: domain-shape evolution is optional-field extension only. New
fields are optional (absent on old peers); no field is retyped and no bound
is silently widened (bounds are target contracts; changing a value requires
an RFC revision, RFC §Rate limits and budgets). The S-1 snapshot correlator,
if AIQ-38 selects S-1, lands later as an optional `params`-JSON field within
the existing `256 KiB` frame and depth-32 bounds — a schema extension, not a
framing change (AIQ-38 open, `bitty-ai-docs#277`). No wire reservation is made
for it here.
