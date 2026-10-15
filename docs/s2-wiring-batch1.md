# S2 transport-wiring readiness, Batch 1 (mechanical)

Scope: wiring items 2, 3, 4, 5, 6, 8 from the review verdict on
`bitty-terminal/bitty-ipc#21` (COMPATIBLE, no envelope reshape). Batch 2
(method names plus required scopes plus per-op consent gating; items 1 and 7)
is a separate later task and is NOT decided here.

Normative base: `bitty-ai-docs` `specifications/ipc-agent-rfc.md` (accepted
2026-08-29; normative on conflict). Every normative-sounding statement below
cites that RFC or is marked `CANDIDATE (CTX-0005)` for security/architecture
reviewer confirmation. S2 shape citations refer to `bitty-ai @ a11bad7`,
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
there.

### IPC-side string byte bounds (currently-unbounded S2 strings)

| S2 field (unbounded today)                                                                                                                                            | IPC-side bound                                           | Precedent                                                                                               |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Selection alias (`SelectEnvelopeRequest.alias`; no validation at construction, `model_selection.rs`)                                                                  | `MAX_AGENT_ALIAS_BYTES = 128` // CANDIDATE (CTX-0005)    | S2 `MAX_MODEL_NAME_LEN` (`128`, same-shape routing-name precedent, `provider_registry.rs`)              |
| `Manifest` strings (`name`, `version`, opaque `host` predicate) and the eight point-descriptor strings ("opaque string only; no validation", `extension_registry.rs`) | `MAX_MANIFEST_FIELD_BYTES = 512` // CANDIDATE (CTX-0005) | S2 `MAX_TOOL_DESCRIPTION_LEN` (`512`, owner-supplied opaque short-string precedent, `tool_dispatch.rs`) |

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

| Flagged case                                                                                                                                              | Worst case                                           | Disposition                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CompleteRequest` chain (`provider_registry.rs`: 128 messages x 16 KiB + 128 refs x 64 B + 32 tools x 64 B = 2,107,392 bytes before JSON overhead)        | ~2 MiB, past both the frame and the RC-9 logical cap | CHUNK via RC-10: the chain crosses as a `seq`/`total` chunk sequence (9 chunks at the cited worst case), never as one logical request past the RC-9 cap (RFC §Rate limits and budgets, RC-9 row). Tested in `limits.rs`.                                                                                                                                                                                              |
| `ContextReadResponse` count-only validation (`context_providers.rs`: `validate` checks counts only, records `<= 128`, absences `<= 64`)                   | Count-valid but byte-heavy response                  | TIGHTEN by layering: the S2 count checks are necessary, not sufficient. The wire layer additionally enforces the `256 KiB` frame bound, depth `<= 32`, and the `1 MiB` logical cap on the wire form, so a count-valid response can still be refused at the wire. No new S2 bound is requested. Tested via `validate_response_envelope` oversize refusal.                                                              |
| Unbounded select chain (`model_selection.rs`: `SelectEnvelopeResponse::Selected` carries a `Vec<SelectedModel>` chain with no envelope-level count bound) | Chain entries scale with registry size               | CHUNK plus TIGHTEN-candidate: any chain length is carried by the RC-10 chunk plan (`chunks_required`, tested), and transport wiring SHOULD cap chain entries — suggested mirror of registry scale (`<= 64`, the S2 `MAX_REGISTERED_MODELS` order) // CANDIDATE (CTX-0005): the envelope is owned by the selection seam and states no bound, so the cap needs reviewer confirmation and must not be enforced silently. |

## Item 4 — S2-refusal to IpcError/Denied-code table

Executable form: `ipc-api/src/refusal.rs` (`AgentRefusal::to_ipc_error`,
total with no wildcard arm). No new `IpcError` variant is introduced; every
class maps onto the accepted RFC error taxonomy (RFC §Wire protocol, "Error
taxonomy"). Refusals carry counts and bounds only, never caller bytes.

| S2 refusal class                                                                              | IPC-side expression                                              | Basis                                                                                                                                                                                                                          |
| --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Unknown` / ack-loss (effect may have happened; reconcile before retry, never blind fallback) | `Unavailable` // CANDIDATE (CTX-0005)                            | Recommended over a new code: the RFC taxonomy already carries "service unavailable" with fail-closed reconcile semantics (RFC §Wire protocol, "Error taxonomy"); a new variant would need an RFC revision.                     |
| `ReservedScopeDenied` (list-style caller scope; MP-4 filtering deferred)                      | `Denied` / `ScopeViolation`                                      | Scope posture denied, but the required-scope registry entries are Batch 2 (item 1), so no `ScopeDenied` scope string is assigned here; Batch 2 may refine to `ScopeDenied`.                                                    |
| `BudgetExceeded { limit, actual }`                                                            | `Denied` / `PayloadCap`                                          | Accepted RC-9 expression for payload past cap, rejected whole (RFC §Rate limits and budgets, RC-9 row; FS-IP1).                                                                                                                |
| `TimeoutTooLarge { max, actual }`                                                             | `InvalidRequest`                                                 | Same shape the channel already enforces at construction (`IpcRequest::new` rejects `timeout_ms` of `0` or past the ceiling with `InvalidRequest`).                                                                             |
| `FallbackError::Malformed` (bad magic, short/overrunning framing, non-UTF-8, trailing bytes)  | `InvalidFrame`                                                   | Nested domain codec failed inside `params`/`result`; the envelope reports the framing failure without further parse (RFC §Wire protocol, envelope rules).                                                                      |
| `CacheHintError::ScopeMismatch`, `KeyMismatch`                                                | `InvalidRequest` // CANDIDATE (CTX-0005)                         | The S2 shape check is a pure equality gate with matching left to the caller, so the IPC expression is a shape refusal, not an authorization verdict; a reviewer could read `ScopeMismatch` as an authorization signal instead. |
| `ContextReadError::EmptyScopes`                                                               | `InvalidRequest`                                                 | Required field missing (FS-IP1 transactional denial).                                                                                                                                                                          |
| `ContextReadError::TooManyScopes` / `TooManyRecords` / `TooManyAbsences`                      | `LimitExceeded { field, limit, actual }` // CANDIDATE (CTX-0005) | Preserves the S2 `{limit, actual}` count pair exactly, matching the codebase pattern for count/length overruns; the alternative is `Denied` / `PayloadCap` (RC-9 language).                                                    |

Known gap (documented, not silently chosen): the S2 provider-authorization
refusal must NOT map to `Unauthenticated` (that class is the transport
peer-credential verdict, RFC §Authentication). Its IPC expression (a new
`Denied` code vs `Unavailable`) stays open for transport scoping.

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
