# S2 transport-wiring readiness, Batch 2 (method registry + consent gating)

Scope: wiring items 1 (method names + required-scope registry entries) and 7
(per-op consent gating) from the review verdict on
`bitty-terminal/bitty-ipc#21` (COMPATIBLE, no envelope reshape). Batch 1
(mechanical bounds, sizes, errors, correlation, deadlines) is recorded in
`docs/s2-wiring-batch1.md` and unchanged here.

Normative base: `bitty-ai-docs` `specifications/ipc-agent-rfc.md` (accepted
2026-08-29; normative on conflict). S2 shape citations refer to
`bitty-ai @ a11bad7`, `crates/bitty-ai-host/src/`, read-only reference; no
`bitty-ai` crate is depended on (dependency direction stays one-way:
`bitty-ai` consumes `bitty-ipc-api`, never the reverse). No
transport/socket code is introduced: this batch is registry data,
server-side authorization, consent-ledger wiring, and tests only.

Executable form: `crates/bitty-ipc-api/src/scope.rs`
(`required_scope_for_method`, `all_known_methods`, `ScopeSet` defaults,
`ConsentLedger`, `authorize_method`). Every policy choice in code is marked
`// POLICY (CTX-0006)` with rationale.

## S-1 context

S-1 is adopted (`bitty-ai-docs#277` closed) and DEC-0004 is accepted
(`bitty-ai-docs#278` closed). If AIQ-38 selects S-1, the snapshot-version
correlator lands later as an optional `params`-JSON field within the
existing `256 KiB` frame and depth-32 bounds — a schema extension, not a
framing change (batch 1, item 8). It does not change this registry: no new
method is reserved for it here, and per-op field schemas for such an
extension ride with the method's `params`, not with new method names.

## Item 1 — Method table (one method per S2 envelope request type)

Single `ai.` namespace; every name passes the wire grammar
(`^[a-z][a-z0-9_]*$` per dot-separated segment, enforced by
`validate_method_name`). Exactly one canonical name per envelope request
type — no aliases, no per-variant fan-out (one `ai.extension_contribute`
covers all eight `ContributionEnvelope` points; the point rides `params`).

| Method                    | Required scope | S2 envelope (request side)                                                                                                               | Why this scope                                                                                                       |
| ------------------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `ai.provider_list`        | `ai.inspect`   | `ListModelsRequest` (`provider_registry.rs`): catalog snapshot, no filter fields; the reserved scoped variant is denied S2-side per MP-4 | Read-only catalog read; no inference, no spend                                                                       |
| `ai.provider_complete`    | `ai.invoke`    | `CompleteRequest` (`provider_registry.rs`): inference execution against a model reference                                                | Effectful: spends budget pre-I/O, consumes the caller deadline, produces untrusted model output                      |
| `ai.model_select`         | `ai.inspect`   | `SelectEnvelopeRequest` (`model_selection.rs`): routing-only selection                                                                   | Returns a detached snapshot chain; no inference, no spend                                                            |
| `ai.model_fallback`       | `ai.inspect`   | `FallbackDirectiveEnvelopeRequest` (`model_selection.rs`): pure classify of an echoed error                                              | Total pure function, no I/O; routed here so every crossing envelope has a scoped method with server-side attribution |
| `ai.model_cost`           | `ai.inspect`   | `EstimateCostEnvelopeRequest` (`model_selection.rs`): pure arithmetic over echoed token/weight inputs                                    | Routing units only, never currency; no spend, no I/O                                                                 |
| `ai.tool_dispatch`        | `ai.invoke`    | `DispatchRequest` (`tool_dispatch.rs`): tool execution                                                                                   | Effectful: executes with filesystem/network authority via the host bus; args cross digest-only                       |
| `ai.context_read`         | `ai.inspect`   | `ContextReadRequest` (`context_providers.rs`): scoped agent-context read                                                                 | Read-only; output is untrusted observation and must never auto-combine with dispatch (RFC consent item 3)            |
| `ai.extension_manifest`   | `ai.inspect`   | `DeclarationEnvelope` (`extension_registry.rs`): manifest declaration echo                                                               | Declaration only; grants nothing, activation not modeled                                                             |
| `ai.extension_contribute` | `ai.inspect`   | `ContributionEnvelope` (`extension_registry.rs`): per-point descriptor echo                                                              | Declaration only; grants nothing                                                                                     |
| `ai.extension_activate`   | `ai.inspect`   | Activation check-named query (`ActivationStub::check_named` shape: point name + enable list; `extension_registry.rs`)                    | Question only, no state change; always denies today under the S3 deny-all posture, layered under the scope gate      |
| `ai.cache_hint`           | `ai.inspect`   | `CacheHintRequest` (`cache_disclosure.rs`): presence-hint query                                                                          | Presence bit only; a hit never authorizes reuse; keys only, no values cross                                          |
| `ai.mcp_pin`              | `ai.inspect`   | `PinEnvelope` (`mcp_placement.rs`): negotiated-protocol-facts echo                                                                       | Data compare only (version + capability shape)                                                                       |
| `ai.mcp_snapshot`         | `ai.inspect`   | `SnapshotEnvelope` (`mcp_placement.rs`): digest-pair snapshot query                                                                      | Digest pairs + echoed version/stale flags only; no enforcement here                                                  |

Registry counts: 38 wire-stable methods before this batch, 51 after (38 + 13).
Unmapped methods still deny `NotFound` — tested with unregistered `ai.evil`
(plus `ai.admin`, `ai.invoke_all`, bare `ai`) against `ScopeSet::all()`:
even every scope granted cannot reach an unregistered name (no
`ai.`-namespace wildcard, FS-IP1).

No scope-hierarchy weakening: `ai.inspect` < `ai.invoke` is authority order
only, matching every existing family (`terminal.inspect` never implies
`terminal.input`, etc.). Authorization is exact-match; `ai.invoke` does not
grant `ai.inspect` methods and `ai.inspect` does not grant `ai.invoke`
methods (tested both directions). Where the hierarchy forced no awkward fit,
none is claimed; had one arisen it would be recorded here as a finding
instead of bending the hierarchy — no such finding arose.

## Item 7 — Per-op consent gating

Defaults (deny-by-default survives on both profiles):

- CLI (`bitty ctl`) default stays 6 scopes (`terminal.inspect`,
  `terminal.input`, `view.inspect`, `view.manage`, `config.inspect`,
  `plugin.inspect`). Neither ai scope is included.
- MCP/Agent default stays 4 read scopes (+ optional `debug.inspect` when
  presented). Neither ai scope is included.
- Hence `requires_elevation` and `requires_mcp_elevation` are true for both
  ai scopes (tested): the first lawful use of any `ai.*` method on either
  profile is an explicit per-client, per-scope, ledgered grant — owner
  prompt or pre-granted per-instance allowlist per the RFC elevation rules.

Ledger wiring: gating flows through the generic `ConsentLedger` with no new
mechanism. Each grant records `who, scope, granted_at, expires_at,
granted_by` (RFC consent item 4); grants are per-`(client_id, scope)`,
never bundled (granting `ai.inspect` never grants `ai.invoke`, tested);
revocation is immediate and expiry returns the client to deny (both tested).
Capacity stays fail-closed at 64 grants (no silent eviction).

Per-effectful-op notes (no consent downgrade):

- `ai.provider_complete`: the method grant authorizes spending inference
  budget under the pre-I/O budget/timeout gates (batch 1, items 3+6). Model
  output crosses back as untrusted observation (RFC consent item 3 applies
  exactly as for terminal content).
- `ai.tool_dispatch`: the method grant (`ai.invoke`, explicit, never
  bundled) is necessary but not sufficient — per-tool consent at execution
  time stays a host-side gate on top (S2 `DenyAllConsent` today). Until the
  host owns per-tool consent, `ai.invoke` grants covering dispatch must
  remain owner-originated, TTL-bounded, and revocable; standing grants are
  deferred, not assumed.
- No `REQUIRES-OWNER` (user) items remain open at the IPC layer: every op
  above has a defined, confident method-level gate. Finer-than-method
  authority (which tool, which args, which budget line) is host-owned and
  listed under deferred, not guessed here.

Echo non-escalation: `AuthBase.level` / `CallerScopeEcho` cross as `params`
data only. `authorize_method` reads solely the server-derived grant set;
top-level `auth`/`scope`/`role` keys are refused at the JSON layer
(batch 1, item 2 rule 5) and any other echoed tier value is opaque ignored
data. Tested: a forged `"All"` tier echo (bare or wrapped) cannot escalate,
and a grant for an unrelated scope (`process.spawn`, `terminal.manage`)
still denies `ai.tool_dispatch`/`ai.provider_complete` with `ScopeDenied`.

## Deferred (not decided here)

1. Per-op `params`/`result` field schemas for the 13 methods (batch-1 item 2
   left schema validation one layer above the channel; the byte/UTF-8/depth
   rules already apply).
2. Host-side per-tool consent and budget enforcement behind
   `ai.tool_dispatch` / `ai.provider_complete` (transport/host wiring, not
   IPC registry work).
3. The optional S-1 snapshot-correlator `params` field (lands with AIQ-38
   selection; schema extension, no method change).
4. The S2 provider-authorization refusal expression left open in batch 1
   (new `Denied` code vs `Unavailable`) — unchanged by this batch.
5. `bitty ctl inspect consent` surfacing of ai grants (candidate inspection
   surface per RFC consent item 4).
