//! Canonical per-method `params`/`result` JSON schemas for the 13 `ai.*`
//! methods (slice S-C, CTX-0011).
//!
//! New module (not a `json.rs` extension): `json.rs` owns the canonical
//! byte rules and stays untouched; per-method field schemas are the layer
//! above it (batch-1 item 2 rule 7), so they live here.
//!
//! Layering, in validation order for every call:
//!
//! 1. Envelope first (`v`/`id`/`method` per `wire.rs`; batch-1 item 2 rule 1).
//! 2. Canonical bytes first: [`validate_ai_params`] and
//!    [`validate_ai_result`] run `json.rs` (`validate_params_json` /
//!    `validate_result_json`: frame bound, UTF-8, depth `<= 32`, no ambient
//!    authority) before interpreting any field.
//! 3. Schema second: the top-level value must be a JSON object whose fields
//!    match the per-method table below, parsed by the headless zero-dependency
//!    parser in this module (depth re-capped at `MAX_JSON_DEPTH`).
//!
//! Unknown-field rule (explicit): unknown fields are REFUSED with
//! [`IpcError::InvalidRequest`], never ignored and never passed through.
//! Fail-closed reasoning: silently ignoring a field would let a caller
//! believe a constraint (a scope echo, a budget, an allow-set) was applied
//! when it was not. Every refusal names the schema-vocabulary field or the
//! bound, never caller bytes.
//!
//! Grammar note (batch-1 item 2 rule 6): the IPC side enforces byte bounds
//! plus UTF-8 only. Name grammars (`MP-2` provider ids, tool names, stable
//! ids, model names) stay S2-owned; over-grammar input crosses and S2
//! refuses it typed. Limits below mirror the S2 `MAX_*` byte/count values
//! exactly; anywhere this module chooses (optionality, defaults, open
//! versus closed vocabulary, uncapped lists) is marked `// POLICY
//! (CTX-0011)` with rationale.
//!
//! Method table (params -> result; `R` = required, `O` = optional+default):
//!
//! - `ai.provider_list`: `{}` (empty body also accepted) ->
//!   `{models: [{provider_id R <=64, name R <=128, capabilities R non-empty
//!   vocab, context_window_tokens R u32, input_cost_weight R u32,
//!   output_cost_weight R u32}] <=64}`.
//! - `ai.provider_complete`: `{model R {provider_id <=64, model <=128},
//!   messages R [{role R vocab, content R <=16KiB}] <=128, context_refs O=[]
//!   (each <=64) <=128, tools O=[] (each <=64 bytes-only) <=32, budget_bytes
//!   R u64 (>= message total), timeout_ms R 1..=30000, now_ms R u64,
//!   sampling O="undeclared" vocab}` -> `{text R <=16KiB, tool_calls R
//!   [{name <=64, arguments R string <=16KiB}] <=8, usage R {4 x u32},
//!   latency_ms R u64}`.
//! - `ai.model_select`: `{required R non-empty vocab array, alias O string
//!   <=128, min_context_window_tokens O u32, max_cost_weight O u32}` ->
//!   `{status R "selected"|"failed", chain R [...] | error R string <=512}`.
//! - `ai.model_fallback`: `{error R 13-variant vocab, detail O string
//!   <=512 default ""}` -> `{directive R "advance"|"stop"}`.
//! - `ai.model_cost`: `{input_tokens, output_tokens R u64, input_weight,
//!   output_weight R u32}` -> same four plus `cost R u64`.
//! - `ai.tool_dispatch`: `{tool R 1..=64 bytes-only, args_digest R u64,
//!   caller R {agent_instance_id, session_id R u64, level R vocab}, allowed O
//!   (absent = no constraint; [] narrows everything away) <=32 of <=64,
//!   now_ms R u64}` -> `{status R 5-axis vocab, result_disposition R
//!   vocab, reason R <=512, usage R {execution_id, tool, args_digest,
//!   occurred_at_ms}}`.
//! - `ai.context_read`: `{scopes R non-empty <=128 of 1..=64 bytes-only,
//!   request R {max_tokens O u32, max_bytes O u64, current_generation R
//!   u64}, detail O="summary" vocab}` -> full assembled shape (see
//!   [`validate_context_read_result`]).
//! - `ai.extension_manifest`: `{manifest R {name, version, host R <=512,
//!   points R 8-point vocab array}}` -> `{manifest: same shape}` echo.
//! - `ai.extension_contribute`: `{point R vocab, value R <=512}` ->
//!   `{point, value}` echo.
//! - `ai.extension_activate`: `{point R open string 1..=128, enabled O=[]
//!   of <=128} <=64` -> no success shape (always refused under deny-all).
//! - `ai.cache_hint`: `{key R {provider_id <=64, model_id <=128, scope R
//!   vocab, stable_prefix_hash R u64, prefix_len R u64 <=96KiB}, ask_scope R
//!   vocab (must equal key.scope), fingerprint R {digest, input_len R u64}}`
//!   -> `{key: same shape, hit R bool}`.
//! - `ai.mcp_pin`: `{}` (empty body also accepted) -> `{protocol_version R
//!   <=128, tools_supported R bool, tools_shape R union}`.
//! - `ai.mcp_snapshot`: `{}` (empty body also accepted) -> `{entries R
//!   [{name <=64, digest R u64}], list_version R u64, list_stale R bool}`.
//!
//! S2 envelope sources below cite `bitty-ai @ b41b55c`,
//! `crates/bitty-ai-host/src/`, read-only reference; no `bitty-ai` crate is
//! depended on.

use crate::error::IpcError;
use crate::json::{
    MAX_MANIFEST_FIELD_BYTES, validate_alias, validate_bounded_string, validate_params_json,
    validate_result_json,
};
use crate::wire::MAX_JSON_DEPTH;

// ── IPC-side schema mirror bounds ───────────────────────────────────────────
// Every value mirrors an S2 `MAX_*` byte/count bound so envelope payloads
// always fit the tables they resolve against. Choices this module makes
// (rather than mirrors) are marked // POLICY (CTX-0011).

/// Maximum bytes per provider id string (`S2 MAX_PROVIDER_ID_LEN`, 64).
pub const MAX_SCHEMA_PROVIDER_ID_BYTES: usize = 64;

/// Maximum bytes per model name string (`S2 MAX_MODEL_NAME_LEN`, 128).
pub const MAX_SCHEMA_MODEL_NAME_BYTES: usize = 128;

/// Maximum bytes per tool name string (`S2 MAX_TOOL_NAME_LEN`, 64; bytes
/// only, no grammar per batch-1 item 2 rule 6).
pub const MAX_SCHEMA_TOOL_NAME_BYTES: usize = 64;

/// Maximum bytes per stable/context id string (`S2 MAX_STABLE_ID_LEN`, 64;
/// bytes only, no grammar per batch-1 item 2 rule 6).
pub const MAX_SCHEMA_STABLE_ID_BYTES: usize = 64;

/// Maximum bytes per context reference string
/// (`S2 MAX_IPC_CONTEXT_REF_BYTES`, 64).
pub const MAX_SCHEMA_CONTEXT_REF_BYTES: usize = 64;

/// Maximum bytes per envelope message content (`S2 MAX_IPC_MESSAGE_BYTES`,
/// 16 KiB).
pub const MAX_SCHEMA_MESSAGE_BYTES: usize = 16 * 1024;

/// Maximum bytes per completion text (`S2 MAX_IPC_TEXT_BYTES`, 16 KiB).
pub const MAX_SCHEMA_TEXT_BYTES: usize = 16 * 1024;

/// Maximum bytes per tool-call arguments JSON text
/// (`S2 MAX_IPC_TOOL_ARGUMENTS_BYTES`, 16 KiB; crosses as a JSON-text
/// string, never raw bytes, so the UTF-8 envelope invariant holds).
pub const MAX_SCHEMA_TOOL_ARGUMENTS_BYTES: usize = 16 * 1024;

/// Maximum bytes per inline record body (`S2 MAX_RECORD_BODY_BYTES`,
/// 16 KiB; crosses as a UTF-8 string — see `content` handling in
/// [`validate_context_read_result`]).
pub const MAX_SCHEMA_RECORD_BODY_BYTES: usize = 16 * 1024;

/// Maximum bytes per record summary (`S2 MAX_SUMMARY_BYTES`, 4 KiB).
pub const MAX_SCHEMA_SUMMARY_BYTES: usize = 4 * 1024;

/// Maximum bytes per diagnostic reason string (`S2 MAX_REASON_BYTES`, 512).
pub const MAX_SCHEMA_REASON_BYTES: usize = 512;

/// Maximum bytes per protocol version string
/// (`S2 MAX_ERROR_NAME_BYTES`, 128; short-name scale precedent).
pub const MAX_SCHEMA_ERROR_NAME_BYTES: usize = 128;

/// Maximum prefix length for a cache-key stable prefix
/// (`S2 MAX_CANONICAL_BYTES`, 96 KiB: a prefix cannot exceed the form).
pub const MAX_SCHEMA_CANONICAL_PREFIX_BYTES: usize = 96 * 1024;

/// Maximum caller timeout in milliseconds (`S2 MAX_REQUEST_TIMEOUT_MS` and
/// the channel construction ceiling, same bound, batch-1 item 6).
pub const MAX_SCHEMA_TIMEOUT_MS: u64 = 30_000;

/// Maximum messages per complete request (`S2 MAX_IPC_MESSAGES`, 128).
pub const MAX_SCHEMA_MESSAGES: usize = 128;

/// Maximum context references per complete request
/// (`S2 MAX_IPC_CONTEXT_REFS`, 128).
pub const MAX_SCHEMA_CONTEXT_REFS: usize = 128;

/// Maximum tool names per complete request (`S2 MAX_IPC_TOOLS`, 32).
pub const MAX_SCHEMA_TOOLS: usize = 32;

/// Maximum tool calls per complete response (`S2 MAX_IPC_TOOL_CALLS`, 8).
pub const MAX_SCHEMA_TOOL_CALLS: usize = 8;

/// Maximum models per list response (`S2 MAX_REGISTERED_MODELS`, 64).
pub const MAX_SCHEMA_MODELS: usize = 64;

/// Maximum records per context read (`S2 MAX_CONTEXT_RECORDS`, 128).
pub const MAX_SCHEMA_RECORDS: usize = 128;

/// Maximum absences per context read response (`S2 MAX_ARTIFACTS`, 64).
pub const MAX_SCHEMA_ABSENCES: usize = 64;

/// Maximum allow-set entries per dispatch echo
/// (`S2 MAX_TOOLS_PER_SESSION`, 32: the echo constrains a registry
/// population of that scale).
pub const MAX_SCHEMA_ALLOWED: usize = 32;

// POLICY (CTX-0011): id-list fields (`context_refs`, `omitted_ids`,
// `pruned_ids`, `truncated_providers`) have no S2 count bound; capped at
// the records scale (128) so truncation bookkeeping cannot bloat past the
// record population it describes. Frame bound governs below this anyway.
pub const MAX_SCHEMA_ID_LIST: usize = 128;

// POLICY (CTX-0011): the activation enable list is accepted-then-ignored
// S2-side (`ActivationStub::check_named`) with no S2 count bound; capped at
// the registry scale (64) so an ignored echo cannot bloat the frame.
pub const MAX_SCHEMA_ENABLE_LIST: usize = 64;

// POLICY (CTX-0011): the activation point name stays an OPEN string (not
// the closed 8-point vocabulary) so unknown names cross and S2 can refuse
// them typed (`UnknownPoint`); the 128-byte bound keeps the echo short.
pub const MAX_SCHEMA_ACTIVATION_POINT_BYTES: usize = 128;

// ── headless JSON parser ────────────────────────────────────────────────────
// Minimal recursive-descent parser over bytes: objects, arrays, strings
// (with escapes), numbers (grammar-checked), literals. Depth re-capped at
// `MAX_JSON_DEPTH` (the canonical layer already confirmed it; this is
// defense in depth for direct callers). No allocation beyond the value
// tree; fails closed on any malformed input.

#[derive(Debug, Clone, PartialEq)]
enum JVal {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<JVal>),
    Obj(Vec<(String, JVal)>),
}

impl JVal {
    /// Unsigned integer value, or `None` for negatives, fractions,
    /// exponents, and overflows (all refusals; integers here are ids,
    /// counts, and byte budgets, never floats).
    fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Num(raw) => {
                if raw.starts_with('-') || raw.bytes().any(|b| b == b'.' || b == b'e' || b == b'E')
                {
                    return None;
                }
                raw.parse::<u64>().ok()
            }
            _ => None,
        }
    }
}

fn invalid_frame(reason: &str) -> IpcError {
    IpcError::InvalidFrame {
        reason: reason.into(),
    }
}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.pos < self.b.len() && matches!(self.b[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn lit(&mut self, word: &str, val: JVal) -> Result<JVal, IpcError> {
        if self.b[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(val)
        } else {
            Err(invalid_frame("json: bad literal"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<JVal, IpcError> {
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(JVal::Str(self.string()?)),
            Some(b't') => self.lit("true", JVal::Bool(true)),
            Some(b'f') => self.lit("false", JVal::Bool(false)),
            Some(b'n') => self.lit("null", JVal::Null),
            Some(b'-') | Some(b'0'..=b'9') => Ok(JVal::Num(self.number()?)),
            Some(_) => Err(invalid_frame("json: unexpected character")),
            None => Err(invalid_frame("json: unexpected end")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<JVal, IpcError> {
        if depth + 1 > MAX_JSON_DEPTH {
            return Err(IpcError::PayloadTooLarge {
                field: "json.depth".into(),
                limit: MAX_JSON_DEPTH,
                actual: depth + 1,
            });
        }
        self.pos += 1; // '{'
        let mut fields = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JVal::Obj(fields));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(invalid_frame("json: object key must be a string"));
            }
            let key = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(invalid_frame("json: object key without colon"));
            }
            self.pos += 1;
            self.ws();
            let val = self.value(depth + 1)?;
            // POLICY (CTX-0011): duplicate keys refused fail-closed (first
            // wins vs last wins is caller-observable ambiguity; neither is
            // chosen silently). The key itself is never echoed: refusals
            // carry no caller bytes.
            if fields.iter().any(|(k, _): &(String, JVal)| *k == key) {
                return Err(IpcError::InvalidRequest {
                    reason: "duplicate object field refused".into(),
                });
            }
            fields.push((key, val));
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JVal::Obj(fields));
                }
                _ => return Err(invalid_frame("json: object separator")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<JVal, IpcError> {
        if depth + 1 > MAX_JSON_DEPTH {
            return Err(IpcError::PayloadTooLarge {
                field: "json.depth".into(),
                limit: MAX_JSON_DEPTH,
                actual: depth + 1,
            });
        }
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JVal::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JVal::Arr(items));
                }
                _ => return Err(invalid_frame("json: array separator")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, IpcError> {
        if self.pos + 4 > self.b.len() {
            return Err(invalid_frame("json: short unicode escape"));
        }
        let mut v = 0u32;
        for i in 0..4 {
            let d = match self.b[self.pos + i] {
                b'0'..=b'9' => (self.b[self.pos + i] - b'0') as u32,
                b'a'..=b'f' => (self.b[self.pos + i] - b'a' + 10) as u32,
                b'A'..=b'F' => (self.b[self.pos + i] - b'A' + 10) as u32,
                _ => return Err(invalid_frame("json: bad unicode escape")),
            };
            v = v * 16 + d;
        }
        self.pos += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, IpcError> {
        self.pos += 1; // '"'
        let mut out = Vec::new();
        loop {
            let c = self
                .peek()
                .ok_or_else(|| invalid_frame("json: unclosed string"))?;
            match c {
                b'"' => {
                    self.pos += 1;
                    break;
                }
                b'\\' => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'"') => {
                            out.push(b'"');
                            self.pos += 1;
                        }
                        Some(b'\\') => {
                            out.push(b'\\');
                            self.pos += 1;
                        }
                        Some(b'/') => {
                            out.push(b'/');
                            self.pos += 1;
                        }
                        Some(b'b') => {
                            out.push(0x08);
                            self.pos += 1;
                        }
                        Some(b'f') => {
                            out.push(0x0C);
                            self.pos += 1;
                        }
                        Some(b'n') => {
                            out.push(b'\n');
                            self.pos += 1;
                        }
                        Some(b'r') => {
                            out.push(b'\r');
                            self.pos += 1;
                        }
                        Some(b't') => {
                            out.push(b'\t');
                            self.pos += 1;
                        }
                        Some(b'u') => {
                            self.pos += 1;
                            let hi = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&hi) {
                                if self.b.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                    return Err(invalid_frame("json: lone surrogate"));
                                }
                                self.pos += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(invalid_frame("json: lone surrogate"));
                                }
                                let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                                char::from_u32(cp)
                                    .ok_or_else(|| invalid_frame("json: bad codepoint"))?
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(invalid_frame("json: lone surrogate"));
                            } else {
                                char::from_u32(hi)
                                    .ok_or_else(|| invalid_frame("json: bad codepoint"))?
                            };
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(invalid_frame("json: bad escape")),
                    }
                }
                0x00..=0x1F => return Err(invalid_frame("json: unescaped control")),
                _ => {
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
        String::from_utf8(out).map_err(|_| invalid_frame("json: invalid utf-8 in string"))
    }

    fn number(&mut self) -> Result<String, IpcError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(invalid_frame("json: bad number")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(invalid_frame("json: bad fraction"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(invalid_frame("json: bad exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        // Fail-closed: leading zeros (`007`) are not JSON; the grammar above
        // accepts the `0` then leaves trailing digits, which must refuse
        // here rather than parse as two tokens.
        if matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(invalid_frame("json: leading zeros"));
        }
        String::from_utf8(self.b[start..self.pos].to_vec())
            .map_err(|_| invalid_frame("json: bad number"))
    }
}

// ── field accessors ─────────────────────────────────────────────────────────
// All refusals name schema-vocabulary fields only, never caller bytes.
// Over-bound strings/counts refuse with `LimitExceeded` (the S2
// `{limit, actual}` pair precedent); every other shape violation refuses
// with `InvalidRequest`.

struct Fields<'a> {
    method: &'static str,
    what: &'static str,
    fields: &'a [(String, JVal)],
}

impl<'a> Fields<'a> {
    fn fail<T>(&self, detail: &str) -> Result<T, IpcError> {
        Err(IpcError::InvalidRequest {
            reason: format!("{} {}: {}", self.method, self.what, detail),
        })
    }

    fn check_known(&self, known: &[&str]) -> Result<(), IpcError> {
        for (k, _) in self.fields {
            if !known.contains(&k.as_str()) {
                return self.fail("unknown field refused");
            }
        }
        Ok(())
    }

    fn req(&self, name: &'static str) -> Result<&'a JVal, IpcError> {
        self.fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
            .ok_or_else(|| IpcError::InvalidRequest {
                reason: format!(
                    "{} {}: missing required field '{}'",
                    self.method, self.what, name
                ),
            })
    }

    fn opt(&self, name: &str) -> Option<&'a JVal> {
        self.fields.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    fn as_str(&self, name: &'static str, v: &'a JVal) -> Result<&'a str, IpcError> {
        match v {
            JVal::Str(s) => Ok(s.as_str()),
            _ => self.fail(&format!("field '{name}' must be a string")),
        }
    }

    fn req_str(&self, name: &'static str) -> Result<&'a str, IpcError> {
        let v = self.req(name)?;
        self.as_str(name, v)
    }

    fn req_bounded(
        &self,
        field: &'static str,
        name: &'static str,
        limit: usize,
    ) -> Result<&'a str, IpcError> {
        let s = self.req_str(name)?;
        validate_bounded_string(field, s, limit)?;
        Ok(s)
    }

    // POLICY (CTX-0011): `field` doubles as the `LimitExceeded` carrier, so
    // dotted schema paths (`model.provider_id`) keep refusals countable
    // without echoing caller bytes.
    fn req_id(
        &self,
        field: &'static str,
        name: &'static str,
        limit: usize,
    ) -> Result<&'a str, IpcError> {
        let s = self.req_str(name)?;
        if s.is_empty() {
            return self.fail(&format!("field '{name}' must be non-empty"));
        }
        validate_bounded_string(field, s, limit)?;
        Ok(s)
    }

    fn opt_bounded(
        &self,
        field: &'static str,
        name: &'static str,
        limit: usize,
    ) -> Result<Option<&'a str>, IpcError> {
        match self.opt(name) {
            None => Ok(None),
            Some(v) => {
                let s = self.as_str(name, v)?;
                validate_bounded_string(field, s, limit)?;
                Ok(Some(s))
            }
        }
    }

    fn req_u64(&self, name: &'static str) -> Result<u64, IpcError> {
        let v = self.req(name)?;
        v.as_u64().ok_or_else(|| IpcError::InvalidRequest {
            reason: format!(
                "{} {}: field '{name}' must be an unsigned integer",
                self.method, self.what
            ),
        })
    }

    fn req_u32(&self, name: &'static str) -> Result<u32, IpcError> {
        let n = self.req_u64(name)?;
        u32::try_from(n).map_err(|_| IpcError::InvalidRequest {
            reason: format!(
                "{} {}: field '{name}' out of range for u32",
                self.method, self.what
            ),
        })
    }

    fn opt_u64(&self, name: &'static str) -> Result<Option<u64>, IpcError> {
        match self.opt(name) {
            None => Ok(None),
            Some(v) => v
                .as_u64()
                .map(Some)
                .ok_or_else(|| IpcError::InvalidRequest {
                    reason: format!(
                        "{} {}: field '{name}' must be an unsigned integer",
                        self.method, self.what
                    ),
                }),
        }
    }

    fn opt_u32(&self, name: &'static str) -> Result<Option<u32>, IpcError> {
        match self.opt_u64(name)? {
            None => Ok(None),
            Some(n) => u32::try_from(n)
                .map(Some)
                .map_err(|_| IpcError::InvalidRequest {
                    reason: format!(
                        "{} {}: field '{name}' out of range for u32",
                        self.method, self.what
                    ),
                }),
        }
    }

    fn req_bool(&self, name: &'static str) -> Result<bool, IpcError> {
        match self.req(name)? {
            JVal::Bool(b) => Ok(*b),
            _ => self.fail(&format!("field '{name}' must be a boolean")),
        }
    }

    fn req_obj(&self, name: &'static str) -> Result<Fields<'a>, IpcError> {
        match self.req(name)? {
            JVal::Obj(f) => Ok(Fields {
                method: self.method,
                what: self.what,
                fields: f,
            }),
            _ => self.fail(&format!("field '{name}' must be an object")),
        }
    }

    fn req_arr(&self, name: &'static str) -> Result<&'a [JVal], IpcError> {
        match self.req(name)? {
            JVal::Arr(items) => Ok(items.as_slice()),
            _ => self.fail(&format!("field '{name}' must be an array")),
        }
    }

    fn req_capped_arr(&self, name: &'static str, max: usize) -> Result<&'a [JVal], IpcError> {
        let items = self.req_arr(name)?;
        if items.len() > max {
            return Err(IpcError::LimitExceeded {
                field: name.into(),
                limit: max,
                actual: items.len(),
            });
        }
        Ok(items)
    }

    fn req_vocab(&self, name: &'static str, allowed: &[&str]) -> Result<&'a str, IpcError> {
        let s = self.req_str(name)?;
        if allowed.contains(&s) {
            Ok(s)
        } else {
            self.fail(&format!("field '{name}' not in closed vocabulary"))
        }
    }

    fn opt_vocab_or(
        &self,
        name: &'static str,
        allowed: &[&str],
        default: &'a str,
    ) -> Result<&'a str, IpcError> {
        match self.opt(name) {
            None => Ok(default),
            Some(v) => {
                let s = self.as_str(name, v)?;
                if allowed.contains(&s) {
                    Ok(s)
                } else {
                    self.fail(&format!("field '{name}' not in closed vocabulary"))
                }
            }
        }
    }
}

// Closed vocabularies. Spellings are IPC-side canonical choices
// (// POLICY (CTX-0011): lowercase snake form of the S2 variant names; the
// S2 enums carry no serialization, so JSON spellings are defined here).

// POLICY (CTX-0011): `ModelCapability` JSON spellings, one per S2 variant.
const CAPABILITIES: &[&str] = &[
    "text",
    "streaming",
    "tool_use",
    "image_input",
    "audio_input",
    "audio_output",
    "video_input",
    "reasoning",
];

// POLICY (CTX-0011): `ExtensionPoint` JSON spellings from
// `activation_point_name` (the closed eight-point vocabulary).
const EXTENSION_POINTS: &[&str] = &[
    "model",
    "tool",
    "context",
    "memory",
    "compactor",
    "agent",
    "command",
    "ui",
];

// POLICY (CTX-0011): `IpcRole` JSON spellings (S2 constructors
// `user`/`assistant`/`tool`).
const ROLES: &[&str] = &["user", "assistant", "tool"];

// POLICY (CTX-0011): `SamplingNote` JSON spellings (`Undeclared` default,
// matching the S2 `#[default]`).
const SAMPLING: &[&str] = &["undeclared", "declared"];

// POLICY (CTX-0011): `AgentLevel` JSON spellings, lowercase of the S2
// variant names. Required (no default): the tier always crosses
// explicitly, never assumed.
const AGENT_LEVELS: &[&str] = &["inspect", "own", "workspace", "all"];

// POLICY (CTX-0011): `DetailLevel` JSON spellings, lowercase of the S2
// variant names.
const DETAIL_LEVELS: &[&str] = &["summary", "standard", "full"];

// POLICY (CTX-0011): `CacheScope` JSON spellings from the S2 `Display`
// (`session`/`turn`/`round`).
const CACHE_SCOPES: &[&str] = &["session", "turn", "round"];

// S2 `ProviderError` variant names (factual taxonomy, snake form): the
// fallback classifier keys on the variant, so params carry the variant
// plus an optional bounded detail instead of re-mirroring 13 payload
// shapes (see `validate_model_fallback_params`).
const PROVIDER_ERRORS: &[&str] = &[
    "unknown_model",
    "budget_exceeded",
    "timeout",
    "timeout_too_large",
    "invalid_provider_id",
    "transport",
    "auth",
    "rate_limited",
    "capability_mismatch",
    "model_unavailable",
    "unknown",
    "invalid_sampling",
    "unsupported_sampling",
];

// POLICY (CTX-0011): `FallbackDirective` JSON spellings, lowercase of the
// S2 `Advance`/`Stop` variants.
const DIRECTIVES: &[&str] = &["advance", "stop"];

// S2 `ToolStatus` axis names (factual 5-variant taxonomy, lowercase); the
// `Rejected` arm lives on `ResultDisposition`, never here.
const TOOL_STATUS: &[&str] = &["success", "failed", "denied", "refused", "unknown"];

// S2 `ResultDisposition` axis names (factual, lowercase).
const DISPOSITIONS: &[&str] = &["accepted", "rejected"];

// S2 `ArtifactAbsence` variant names (factual taxonomy, snake form).
const ABSENCES: &[&str] = &[
    "available",
    "never_recorded",
    "missing",
    "deleted",
    "expired",
];

// S2 `ToolsCapabilityShape` JSON spellings: `bool_true` for `"tools": true`,
// `object` for `"tools": {...}`.
const TOOL_SHAPE_KINDS: &[&str] = &["bool_true", "object"];

// S2 envelope selection discriminator for the response union.
const SELECT_STATUS: &[&str] = &["selected", "failed"];

// S2 `AssembledContent` arm spellings.
const CONTENT_KINDS: &[&str] = &["inline", "reference"];

// ── shared shapes ───────────────────────────────────────────────────────────

// S2 `ModelRegistration` snapshot entry (provider catalog entries and
// selection chain elements share this shape: provider association plus
// routing metadata; `0` context window means unknown, `0` weight means
// uncalibrated baseline `1` — data, never enforced here).
fn check_model_entry(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&[
        "provider_id",
        "name",
        "capabilities",
        "context_window_tokens",
        "input_cost_weight",
        "output_cost_weight",
    ])?;
    // POLICY (CTX-0011): bytes only, no `MP-2`/name grammar (batch-1 item 2
    // rule 6); grammar stays S2-owned.
    f.req_id("provider_id", "provider_id", MAX_SCHEMA_PROVIDER_ID_BYTES)?;
    f.req_id("name", "name", MAX_SCHEMA_MODEL_NAME_BYTES)?;
    let caps = f.req_arr("capabilities")?;
    // POLICY (CTX-0011): non-empty mirrors the S2 registration invariant
    // ("at least one"); no count cap beyond the frame bound — duplicates
    // are harmless under subset-match semantics.
    if caps.is_empty() {
        return f.fail("field 'capabilities' must be non-empty");
    }
    for c in caps {
        match c {
            JVal::Str(s) if CAPABILITIES.contains(&s.as_str()) => {}
            _ => return f.fail("capability not in closed vocabulary"),
        }
    }
    f.req_u32("context_window_tokens")?;
    f.req_u32("input_cost_weight")?;
    f.req_u32("output_cost_weight")?;
    Ok(())
}

// S2 `CacheKey` echo (keys only, never values; equality stays caller-side).
fn check_cache_key(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&[
        "provider_id",
        "model_id",
        "scope",
        "stable_prefix_hash",
        "prefix_len",
    ])?;
    f.req_id(
        "key.provider_id",
        "provider_id",
        MAX_SCHEMA_PROVIDER_ID_BYTES,
    )?;
    f.req_id("key.model_id", "model_id", MAX_SCHEMA_MODEL_NAME_BYTES)?;
    f.req_vocab("scope", CACHE_SCOPES)?;
    f.req_u64("stable_prefix_hash")?;
    let prefix_len = f.req_u64("prefix_len")?;
    // POLICY (CTX-0011): prefix cannot exceed the canonical form it hashes
    // (S2 `MAX_CANONICAL_BYTES`); expression mirrors the count/length
    // `LimitExceeded` pattern.
    if prefix_len > MAX_SCHEMA_CANONICAL_PREFIX_BYTES as u64 {
        return Err(IpcError::LimitExceeded {
            field: "key.prefix_len".into(),
            limit: MAX_SCHEMA_CANONICAL_PREFIX_BYTES,
            actual: prefix_len as usize,
        });
    }
    Ok(())
}

// S2 `Manifest` declaration echo (opaque strings; `host` never parsed).
fn check_manifest(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&["name", "version", "host", "points"])?;
    f.req_bounded("manifest.name", "name", MAX_MANIFEST_FIELD_BYTES)?;
    f.req_bounded("manifest.version", "version", MAX_MANIFEST_FIELD_BYTES)?;
    f.req_bounded("manifest.host", "host", MAX_MANIFEST_FIELD_BYTES)?;
    let points = f.req_arr("points")?;
    // POLICY (CTX-0011): empty points allowed (declares nothing, grants
    // nothing); duplicates allowed (harmless declaration echo).
    for p in points {
        match p {
            JVal::Str(s) if EXTENSION_POINTS.contains(&s.as_str()) => {}
            _ => return f.fail("point not in closed vocabulary"),
        }
    }
    Ok(())
}

// ── per-method params ───────────────────────────────────────────────────────

fn validate_provider_list_params(f: &Fields<'_>) -> Result<(), IpcError> {
    // No filter fields: the only accepted shape is the unfiltered request
    // (S2 `ListModelsRequest::unfiltered`; the reserved scoped variant is
    // denied S2-side per MP-4, so `caller_scope`/`scope` must never cross
    // and refuse here as unknown).
    f.check_known(&[])?;
    Ok(())
}

fn validate_provider_complete_params(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&[
        "model",
        "messages",
        "context_refs",
        "tools",
        "budget_bytes",
        "timeout_ms",
        "now_ms",
        "sampling",
    ])?;
    let model = f.req_obj("model")?;
    model.check_known(&["provider_id", "model"])?;
    model.req_id(
        "model.provider_id",
        "provider_id",
        MAX_SCHEMA_PROVIDER_ID_BYTES,
    )?;
    model.req_id("model.model", "model", MAX_SCHEMA_MODEL_NAME_BYTES)?;
    let messages = f.req_capped_arr("messages", MAX_SCHEMA_MESSAGES)?;
    // POLICY (CTX-0011): empty messages allowed (S2 `check` states no
    // non-empty invariant; execution decides admission).
    let mut total_bytes = 0usize;
    for (i, m) in messages.iter().enumerate() {
        let mf = match m {
            JVal::Obj(fields) => Fields {
                method: f.method,
                what: f.what,
                fields,
            },
            _ => return f.fail(&format!("messages[{i}] must be an object")),
        };
        mf.check_known(&["role", "content"])?;
        mf.req_vocab("role", ROLES)?;
        let content = mf.req_str("content")?;
        if content.len() > MAX_SCHEMA_MESSAGE_BYTES {
            return Err(IpcError::LimitExceeded {
                field: "messages.content".into(),
                limit: MAX_SCHEMA_MESSAGE_BYTES,
                actual: content.len(),
            });
        }
        total_bytes = total_bytes.saturating_add(content.len());
    }
    // POLICY (CTX-0011): optional, default `[]` (absent = no refs; least
    // data crosses).
    if let Some(v) = f.opt("context_refs") {
        let refs = match v {
            JVal::Arr(items) => items.as_slice(),
            _ => return f.fail("field 'context_refs' must be an array"),
        };
        if refs.len() > MAX_SCHEMA_CONTEXT_REFS {
            return Err(IpcError::LimitExceeded {
                field: "context_refs".into(),
                limit: MAX_SCHEMA_CONTEXT_REFS,
                actual: refs.len(),
            });
        }
        for r in refs {
            match r {
                JVal::Str(s) if !s.is_empty() && s.len() <= MAX_SCHEMA_CONTEXT_REF_BYTES => {}
                JVal::Str(_) => {
                    return Err(IpcError::LimitExceeded {
                        field: "context_refs".into(),
                        limit: MAX_SCHEMA_CONTEXT_REF_BYTES,
                        actual: match r {
                            JVal::Str(s) => s.len(),
                            _ => 0,
                        },
                    });
                }
                _ => return f.fail("context_refs entries must be strings"),
            }
        }
    }
    // POLICY (CTX-0011): optional, default `[]`; bytes only, no tool-name
    // grammar (batch-1 item 2 rule 6).
    if let Some(v) = f.opt("tools") {
        let tools = match v {
            JVal::Arr(items) => items.as_slice(),
            _ => return f.fail("field 'tools' must be an array"),
        };
        if tools.len() > MAX_SCHEMA_TOOLS {
            return Err(IpcError::LimitExceeded {
                field: "tools".into(),
                limit: MAX_SCHEMA_TOOLS,
                actual: tools.len(),
            });
        }
        for t in tools {
            match t {
                JVal::Str(s) if !s.is_empty() && s.len() <= MAX_SCHEMA_TOOL_NAME_BYTES => {}
                JVal::Str(s) => {
                    return Err(IpcError::LimitExceeded {
                        field: "tools".into(),
                        limit: MAX_SCHEMA_TOOL_NAME_BYTES,
                        actual: s.len(),
                    });
                }
                _ => return f.fail("tools entries must be strings"),
            }
        }
    }
    let budget = f.req_u64("budget_bytes")?;
    // POLICY (CTX-0011): message total must fit the declared budget
    // (mirrors S2 `BudgetExceeded { limit, actual }`; expression follows
    // the count/length `LimitExceeded` precedent).
    if total_bytes as u64 > budget {
        return Err(IpcError::LimitExceeded {
            field: "budget_bytes".into(),
            limit: budget as usize,
            actual: total_bytes,
        });
    }
    let timeout = f.req_u64("timeout_ms")?;
    // `0` refused (mirrors channel construction) and past-ceiling refused
    // (S2 `TimeoutTooLarge` maps to `InvalidRequest` per batch-1 item 4).
    if timeout == 0 || timeout > MAX_SCHEMA_TIMEOUT_MS {
        return f.fail("field 'timeout_ms' must be 1..=30000");
    }
    f.req_u64("now_ms")?;
    // POLICY (CTX-0011): optional, default `"undeclared"` (matches the S2
    // `#[default]`; absent flows through untouched).
    f.opt_vocab_or("sampling", SAMPLING, "undeclared")?;
    Ok(())
}

fn validate_model_select_params(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&[
        "required",
        "alias",
        "min_context_window_tokens",
        "max_cost_weight",
    ])?;
    let required = f.req_arr("required")?;
    // S2 `SelectEnvelopeRequest` narrows only: selection never matches
    // without capabilities, so empty refuses (missing narrowing).
    if required.is_empty() {
        return f.fail("field 'required' must be non-empty");
    }
    // POLICY (CTX-0011): no count cap beyond the frame bound (closed
    // vocabulary; duplicates harmless under all-match semantics).
    for c in required {
        match c {
            JVal::Str(s) if CAPABILITIES.contains(&s.as_str()) => {}
            _ => return f.fail("capability not in closed vocabulary"),
        }
    }
    // POLICY (CTX-0011): optional alias (`None` when absent); bound reuses
    // `validate_alias` so the `LimitExceeded` shape matches `json.rs`.
    if let Some(v) = f.opt("alias") {
        let s = f.as_str("alias", v)?;
        validate_alias(s)?;
    }
    // POLICY (CTX-0011): both narrowing bounds optional (`None` when
    // absent; narrowing never widens, so absent constrains nothing).
    f.opt_u32("min_context_window_tokens")?;
    f.opt_u32("max_cost_weight")?;
    Ok(())
}

fn validate_model_fallback_params(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&["error", "detail"])?;
    // POLICY (CTX-0011): the echoed error crosses as its variant name only.
    // Classification keys on the variant (`fallback_directive` is total over
    // it); the 13 payload shapes (limits, providers, reasons) stay S2-side
    // and are not re-mirrored here.
    f.req_vocab("error", PROVIDER_ERRORS)?;
    // POLICY (CTX-0011): optional bounded detail carrier (provider/reason
    // text at the reason scale), default `""`; grammar S2-owned.
    f.opt_bounded("detail", "detail", MAX_SCHEMA_REASON_BYTES)?;
    Ok(())
}

fn validate_model_cost_params(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&[
        "input_tokens",
        "output_tokens",
        "input_weight",
        "output_weight",
    ])?;
    // All four `estimate_cost` inputs required: `0` weights are meaningful
    // (uncalibrated baseline `1`), so no field may be omitted in favor of a
    // default zero.
    f.req_u64("input_tokens")?;
    f.req_u64("output_tokens")?;
    f.req_u32("input_weight")?;
    f.req_u32("output_weight")?;
    Ok(())
}

fn validate_tool_dispatch_params(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&["tool", "args_digest", "caller", "allowed", "now_ms"])?;
    // POLICY (CTX-0011): bytes only plus non-empty, no `^[a-z]...` grammar
    // (batch-1 item 2 rule 6); malformed names cross and S2 refuses typed.
    f.req_id("tool", "tool", MAX_SCHEMA_TOOL_NAME_BYTES)?;
    // Digest only, never raw args (S2 `UsageEvent::args_digest` precedent):
    // the transport binds its own argument bytes out-of-band.
    f.req_u64("args_digest")?;
    let caller = f.req_obj("caller")?;
    caller.check_known(&["agent_instance_id", "session_id", "level"])?;
    caller.req_u64("agent_instance_id")?;
    caller.req_u64("session_id")?;
    // POLICY (CTX-0011): tier required with no default (never assumed; the
    // server re-derives authority from identity regardless).
    caller.req_vocab("level", AGENT_LEVELS)?;
    // POLICY (CTX-0011): absent allow-set (`None`) constrains nothing; an
    // explicit empty list narrows everything away (mirrors S2
    // `narrowing_omits`); entries are bytes-only tool names.
    if let Some(v) = f.opt("allowed") {
        let allowed = match v {
            JVal::Arr(items) => items.as_slice(),
            _ => return f.fail("field 'allowed' must be an array or absent"),
        };
        if allowed.len() > MAX_SCHEMA_ALLOWED {
            return Err(IpcError::LimitExceeded {
                field: "allowed".into(),
                limit: MAX_SCHEMA_ALLOWED,
                actual: allowed.len(),
            });
        }
        for a in allowed {
            match a {
                JVal::Str(s) if !s.is_empty() && s.len() <= MAX_SCHEMA_TOOL_NAME_BYTES => {}
                JVal::Str(s) => {
                    return Err(IpcError::LimitExceeded {
                        field: "allowed".into(),
                        limit: MAX_SCHEMA_TOOL_NAME_BYTES,
                        actual: s.len(),
                    });
                }
                _ => return f.fail("allowed entries must be strings"),
            }
        }
    }
    f.req_u64("now_ms")?;
    Ok(())
}

fn validate_context_read_params(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&["scopes", "request", "detail"])?;
    let scopes = f.req_capped_arr("scopes", MAX_SCHEMA_RECORDS)?;
    // S2 `ContextReadRequest::validate`: non-empty, at most
    // `MAX_CONTEXT_RECORDS`.
    if scopes.is_empty() {
        return f.fail("field 'scopes' must be non-empty");
    }
    // POLICY (CTX-0011): bytes only plus non-empty, no stable-id grammar
    // (batch-1 item 2 rule 6).
    for s in scopes {
        match s {
            JVal::Str(id) if !id.is_empty() && id.len() <= MAX_SCHEMA_STABLE_ID_BYTES => {}
            JVal::Str(id) => {
                return Err(IpcError::LimitExceeded {
                    field: "scopes".into(),
                    limit: MAX_SCHEMA_STABLE_ID_BYTES,
                    actual: id.len(),
                });
            }
            _ => return f.fail("scopes entries must be strings"),
        }
    }
    let request = f.req_obj("request")?;
    request.check_known(&["max_tokens", "max_bytes", "current_generation"])?;
    // POLICY (CTX-0011): ceilings optional (absent = S2 server-side
    // default via `effective_budget_bytes`); no numeric default is
    // invented here.
    request.opt_u32("max_tokens")?;
    request.opt_u64("max_bytes")?;
    request.req_u64("current_generation")?;
    // POLICY (CTX-0011): optional, default `"summary"` (least data: the
    // read-only default exposes references only until asked for more).
    f.opt_vocab_or("detail", DETAIL_LEVELS, "summary")?;
    Ok(())
}

fn validate_extension_manifest_params(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&["manifest"])?;
    let manifest = f.req_obj("manifest")?;
    check_manifest(&manifest)?;
    Ok(())
}

fn validate_extension_contribute_params(f: &Fields<'_>) -> Result<(), IpcError> {
    // One method covers all eight points (no per-variant fan-out); the
    // point rides params as closed vocabulary, the descriptor as one
    // opaque bounded string (whichever `*Descriptor` field the S1 point
    // shape carries).
    f.check_known(&["point", "value"])?;
    f.req_vocab("point", EXTENSION_POINTS)?;
    f.req_bounded("value", "value", MAX_MANIFEST_FIELD_BYTES)?;
    Ok(())
}

fn validate_extension_activate_params(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&["point", "enabled"])?;
    // POLICY (CTX-0011): OPEN string (see const rationale): unknown names
    // must cross so S2 refuses typed `UnknownPoint`.
    f.req_id("point", "point", MAX_SCHEMA_ACTIVATION_POINT_BYTES)?;
    // POLICY (CTX-0011): optional enable list, default `[]`; accepted for
    // signature compatibility then ignored fail-closed S2-side.
    if let Some(v) = f.opt("enabled") {
        let enabled = match v {
            JVal::Arr(items) => items.as_slice(),
            _ => return f.fail("field 'enabled' must be an array or absent"),
        };
        if enabled.len() > MAX_SCHEMA_ENABLE_LIST {
            return Err(IpcError::LimitExceeded {
                field: "enabled".into(),
                limit: MAX_SCHEMA_ENABLE_LIST,
                actual: enabled.len(),
            });
        }
        for e in enabled {
            match e {
                JVal::Str(s) if !s.is_empty() && s.len() <= MAX_SCHEMA_ACTIVATION_POINT_BYTES => {}
                JVal::Str(s) => {
                    return Err(IpcError::LimitExceeded {
                        field: "enabled".into(),
                        limit: MAX_SCHEMA_ACTIVATION_POINT_BYTES,
                        actual: s.len(),
                    });
                }
                _ => return f.fail("enabled entries must be strings"),
            }
        }
    }
    Ok(())
}

fn validate_cache_hint_params(f: &Fields<'_>) -> Result<(), IpcError> {
    // POLICY (CTX-0011): the asked-scope field is named `ask_scope`, NOT
    // `scope`: a top-level `scope` key trips the canonical
    // no-ambient-authority rule (batch-1 item 2 rule 5) before any schema
    // byte is interpreted, and an authority-shaped echo must never share a
    // name with an authority assertion. The nested `key.scope` is data at
    // depth 2 and keeps the S2 field name.
    f.check_known(&["key", "ask_scope", "fingerprint"])?;
    let key = f.req_obj("key")?;
    check_cache_key(&key)?;
    let ask_scope = f.req_vocab("ask_scope", CACHE_SCOPES)?;
    let print = f.req_obj("fingerprint")?;
    print.check_known(&["digest", "input_len"])?;
    print.req_u64("digest")?;
    // POLICY (CTX-0011): total fingerprinted bytes unbounded (the digest
    // covers the complete input; no S2 cap states one).
    print.req_u64("input_len")?;
    // Mirrors S2 `CacheHintRequest::validate`: the asked scope must equal
    // the key scope (shape check, `InvalidRequest` expression per batch-1
    // item 4 mapping).
    let key_scope = key.req_vocab("scope", CACHE_SCOPES)?;
    if ask_scope != key_scope {
        return f.fail("field 'ask_scope' must equal key scope");
    }
    Ok(())
}

fn validate_mcp_pin_params(f: &Fields<'_>) -> Result<(), IpcError> {
    // Pin query carries no fields: the pin is server-echoed state compared
    // data-only (`PinEnvelope::matches`); nothing is filtered by.
    f.check_known(&[])?;
    Ok(())
}

fn validate_mcp_snapshot_params(f: &Fields<'_>) -> Result<(), IpcError> {
    // Snapshot query carries no fields: digest pairs plus version/stale
    // flags echo back as data with no enforcement here.
    f.check_known(&[])?;
    Ok(())
}

// ── per-method results ──────────────────────────────────────────────────────

fn validate_provider_list_result(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&["models"])?;
    let models = f.req_capped_arr("models", MAX_SCHEMA_MODELS)?;
    for m in models {
        match m {
            JVal::Obj(fields) => check_model_entry(&Fields {
                method: f.method,
                what: f.what,
                fields,
            })?,
            _ => return f.fail("models entries must be objects"),
        }
    }
    Ok(())
}

fn validate_provider_complete_result(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&["text", "tool_calls", "usage", "latency_ms"])?;
    f.req_bounded("text", "text", MAX_SCHEMA_TEXT_BYTES)?;
    let calls = f.req_capped_arr("tool_calls", MAX_SCHEMA_TOOL_CALLS)?;
    for (i, c) in calls.iter().enumerate() {
        let cf = match c {
            JVal::Obj(fields) => Fields {
                method: f.method,
                what: f.what,
                fields,
            },
            _ => return f.fail(&format!("tool_calls[{i}] must be an object")),
        };
        cf.check_known(&["name", "arguments"])?;
        cf.req_id("tool_calls.name", "name", MAX_SCHEMA_TOOL_NAME_BYTES)?;
        // POLICY (CTX-0011): opaque arguments cross as a JSON-text string
        // (never raw bytes, preserving the UTF-8 envelope invariant).
        cf.req_bounded(
            "tool_calls.arguments",
            "arguments",
            MAX_SCHEMA_TOOL_ARGUMENTS_BYTES,
        )?;
    }
    let usage = f.req_obj("usage")?;
    usage.check_known(&[
        "input_tokens",
        "output_tokens",
        "cached_tokens",
        "cache_write_tokens",
    ])?;
    // Observed token accounting (`0` = unreported, never measured zero).
    usage.req_u32("input_tokens")?;
    usage.req_u32("output_tokens")?;
    usage.req_u32("cached_tokens")?;
    usage.req_u32("cache_write_tokens")?;
    f.req_u64("latency_ms")?;
    Ok(())
}

fn validate_model_select_result(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&["status", "chain", "error"])?;
    match f.req_vocab("status", SELECT_STATUS)? {
        "selected" => {
            let chain = f.req_arr("chain")?;
            // POLICY (CTX-0011): chain count NOT capped (batch-1 item 3
            // suggests `<= 64` as CANDIDATE (CTX-0005) needing reviewer
            // confirmation; enforcing silently is forbidden, so the frame
            // bound governs until confirmed).
            for c in chain {
                match c {
                    JVal::Obj(fields) => check_model_entry(&Fields {
                        method: f.method,
                        what: f.what,
                        fields,
                    })?,
                    _ => return f.fail("chain entries must be objects"),
                }
            }
            if f.opt("error").is_some() {
                return f.fail("selected result must not carry error");
            }
        }
        _ => {
            // POLICY (CTX-0011): the refusal crosses as one bounded
            // diagnostic string; no `SelectionError` taxonomy is
            // re-mirrored (kind mapping stays with CTX-0012 refusal work).
            f.req_bounded("error", "error", MAX_SCHEMA_REASON_BYTES)?;
            if f.opt("chain").is_some() {
                return f.fail("failed result must not carry chain");
            }
        }
    }
    Ok(())
}

fn validate_model_fallback_result(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&["directive"])?;
    f.req_vocab("directive", DIRECTIVES)?;
    Ok(())
}

fn validate_model_cost_result(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&[
        "input_tokens",
        "output_tokens",
        "input_weight",
        "output_weight",
        "cost",
    ])?;
    f.req_u64("input_tokens")?;
    f.req_u64("output_tokens")?;
    f.req_u32("input_weight")?;
    f.req_u32("output_weight")?;
    f.req_u64("cost")?;
    // POLICY (CTX-0011): consistency (`cost == estimate(...)`) is S2-owned
    // (`is_consistent`); the schema checks shapes only.
    Ok(())
}

fn validate_tool_dispatch_result(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&["status", "result_disposition", "reason", "usage"])?;
    f.req_vocab("status", TOOL_STATUS)?;
    f.req_vocab("result_disposition", DISPOSITIONS)?;
    // Bounded diagnostic (`bound_reason` scale; empty for success).
    f.req_bounded("reason", "reason", MAX_SCHEMA_REASON_BYTES)?;
    let usage = f.req_obj("usage")?;
    // POLICY (CTX-0011): the usage echo crosses as attribution scalars
    // only (handles, tool name, digest, timestamp). Richer S2 detail
    // (required-scope strings, server/task labels, placement, typed
    // error causes) stays host-side and never crosses.
    usage.check_known(&["execution_id", "tool", "args_digest", "occurred_at_ms"])?;
    usage.req_u64("execution_id")?;
    usage.req_id("usage.tool", "tool", MAX_SCHEMA_TOOL_NAME_BYTES)?;
    usage.req_u64("args_digest")?;
    usage.req_u64("occurred_at_ms")?;
    Ok(())
}

fn check_id_list(f: &Fields<'_>, name: &'static str, items: &[JVal]) -> Result<(), IpcError> {
    // POLICY (CTX-0011): shared 128-entry / 64-byte shape for truncation
    // bookkeeping lists (see `MAX_SCHEMA_ID_LIST`).
    if items.len() > MAX_SCHEMA_ID_LIST {
        return Err(IpcError::LimitExceeded {
            field: name.into(),
            limit: MAX_SCHEMA_ID_LIST,
            actual: items.len(),
        });
    }
    for e in items {
        match e {
            JVal::Str(s) if !s.is_empty() && s.len() <= MAX_SCHEMA_STABLE_ID_BYTES => {}
            JVal::Str(s) => {
                return Err(IpcError::LimitExceeded {
                    field: name.into(),
                    limit: MAX_SCHEMA_STABLE_ID_BYTES,
                    actual: s.len(),
                });
            }
            _ => return f.fail(&format!("field '{name}' entries must be strings")),
        }
    }
    Ok(())
}

fn validate_context_read_result(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&[
        "current_generation",
        "records",
        "context_refs",
        "omitted_ids",
        "pruned_ids",
        "externalized",
        "truncated_bytes",
        "truncated_tokens_estimate",
        "truncated_providers",
        "budget_bytes",
        "absences",
    ])?;
    f.req_u64("current_generation")?;
    let records = f.req_capped_arr("records", MAX_SCHEMA_RECORDS)?;
    for (i, r) in records.iter().enumerate() {
        let rf = match r {
            JVal::Obj(fields) => Fields {
                method: f.method,
                what: f.what,
                fields,
            },
            _ => return f.fail(&format!("records[{i}] must be an object")),
        };
        rf.check_known(&[
            "id",
            "provider",
            "summary",
            "content",
            "is_untrusted_surface",
        ])?;
        rf.req_id("records.id", "id", MAX_SCHEMA_STABLE_ID_BYTES)?;
        rf.req_id("records.provider", "provider", MAX_SCHEMA_PROVIDER_ID_BYTES)?;
        rf.req_bounded("records.summary", "summary", MAX_SCHEMA_SUMMARY_BYTES)?;
        let content = rf.req_obj("content")?;
        content.check_known(&["kind", "body", "reference"])?;
        match content.req_vocab("kind", CONTENT_KINDS)? {
            "inline" => {
                // POLICY (CTX-0011): inline bytes cross as a UTF-8 string;
                // non-UTF-8 payloads cannot use this arm and stay
                // externalized behind a reference.
                content.req_bounded(
                    "records.content.body",
                    "body",
                    MAX_SCHEMA_RECORD_BODY_BYTES,
                )?;
                if content.opt("reference").is_some() {
                    return f.fail("inline content must not carry reference");
                }
            }
            _ => {
                content.req_id(
                    "records.content.reference",
                    "reference",
                    MAX_SCHEMA_STABLE_ID_BYTES,
                )?;
                if content.opt("body").is_some() {
                    return f.fail("reference content must not carry body");
                }
            }
        }
        match rf.req("is_untrusted_surface")? {
            JVal::Bool(_) => {}
            _ => return f.fail("field 'is_untrusted_surface' must be a boolean"),
        }
    }
    check_id_list(f, "context_refs", f.req_arr("context_refs")?)?;
    check_id_list(f, "omitted_ids", f.req_arr("omitted_ids")?)?;
    check_id_list(f, "pruned_ids", f.req_arr("pruned_ids")?)?;
    f.req_u64("externalized")?;
    f.req_u64("truncated_bytes")?;
    f.req_u64("truncated_tokens_estimate")?;
    check_id_list(f, "truncated_providers", f.req_arr("truncated_providers")?)?;
    f.req_u64("budget_bytes")?;
    let absences = f.req_capped_arr("absences", MAX_SCHEMA_ABSENCES)?;
    for (i, a) in absences.iter().enumerate() {
        let af = match a {
            JVal::Obj(fields) => Fields {
                method: f.method,
                what: f.what,
                fields,
            },
            _ => return f.fail(&format!("absences[{i}] must be an object")),
        };
        af.check_known(&["reference", "absence"])?;
        af.req_id(
            "absences.reference",
            "reference",
            MAX_SCHEMA_STABLE_ID_BYTES,
        )?;
        af.req_vocab("absence", ABSENCES)?;
    }
    Ok(())
}

fn validate_extension_manifest_result(f: &Fields<'_>) -> Result<(), IpcError> {
    // Declaration echo: the manifest crosses back verbatim under the same
    // bounds (grants nothing either direction).
    f.check_known(&["manifest"])?;
    let manifest = f.req_obj("manifest")?;
    check_manifest(&manifest)?;
    Ok(())
}

fn validate_extension_contribute_result(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&["point", "value"])?;
    f.req_vocab("point", EXTENSION_POINTS)?;
    f.req_bounded("value", "value", MAX_MANIFEST_FIELD_BYTES)?;
    Ok(())
}

fn validate_extension_activate_result(f: &Fields<'_>) -> Result<(), IpcError> {
    // POLICY (CTX-0011): no success shape exists under the S3 deny-all
    // posture (`ActivationStub` denies every activation, known or unknown),
    // so any result body — including an empty one — refuses. A future
    // admission posture defines a shape here.
    let _ = f;
    Err(IpcError::InvalidRequest {
        reason: "ai.extension_activate result: no success shape under deny-all".into(),
    })
}

fn validate_cache_hint_result(f: &Fields<'_>) -> Result<(), IpcError> {
    // Presence bit only; a hit never authorizes reuse and no value crosses.
    f.check_known(&["key", "hit"])?;
    let key = f.req_obj("key")?;
    check_cache_key(&key)?;
    f.req_bool("hit")?;
    Ok(())
}

fn validate_mcp_pin_result(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&["protocol_version", "tools_supported", "tools_shape"])?;
    f.req_id(
        "protocol_version",
        "protocol_version",
        MAX_SCHEMA_ERROR_NAME_BYTES,
    )?;
    f.req_bool("tools_supported")?;
    let shape = f.req_obj("tools_shape")?;
    shape.check_known(&["kind", "list_changed"])?;
    match shape.req_vocab("kind", TOOL_SHAPE_KINDS)? {
        "bool_true" => {
            if shape.opt("list_changed").is_some() {
                return f.fail("bool_true shape must not carry list_changed");
            }
        }
        _ => {
            // POLICY (CTX-0011): absent or explicit null means `None`
            // (no flag threaded); any other non-boolean refuses.
            match shape.opt("list_changed") {
                None | Some(JVal::Null) => {}
                Some(JVal::Bool(_)) => {}
                Some(_) => return f.fail("field 'list_changed' must be a boolean or null"),
            }
        }
    }
    // POLICY (CTX-0011): pin VALUES are not enforced here (version pin and
    // tools-capability presence are S2 `PinEnvelope::validate`
    // refusals); the schema checks shapes only, so drift data still
    // crosses for `matches` comparison.
    Ok(())
}

fn validate_mcp_snapshot_result(f: &Fields<'_>) -> Result<(), IpcError> {
    f.check_known(&["entries", "list_version", "list_stale"])?;
    let entries = f.req_arr("entries")?;
    // POLICY (CTX-0011): entry count uncapped (scales with the import
    // population; no S2 count bound states one — the frame bound governs).
    for (i, e) in entries.iter().enumerate() {
        let ef = match e {
            JVal::Obj(fields) => Fields {
                method: f.method,
                what: f.what,
                fields,
            },
            _ => return f.fail(&format!("entries[{i}] must be an object")),
        };
        ef.check_known(&["name", "digest"])?;
        // Sanitized names reuse the tool-name byte scale (S1
        // `MAX_TOOL_NAME_LEN`); digests are opaque u64s.
        ef.req_id("entries.name", "name", MAX_SCHEMA_TOOL_NAME_BYTES)?;
        ef.req_u64("digest")?;
    }
    f.req_u64("list_version")?;
    f.req_bool("list_stale")?;
    Ok(())
}

// ── dispatch ────────────────────────────────────────────────────────────────

type SchemaFn = fn(&Fields<'_>) -> Result<(), IpcError>;

fn ai_handlers(method: &str) -> Option<(&'static str, SchemaFn, SchemaFn)> {
    match method {
        "ai.provider_list" => Some((
            "ai.provider_list",
            validate_provider_list_params as SchemaFn,
            validate_provider_list_result as SchemaFn,
        )),
        "ai.provider_complete" => Some((
            "ai.provider_complete",
            validate_provider_complete_params as SchemaFn,
            validate_provider_complete_result as SchemaFn,
        )),
        "ai.model_select" => Some((
            "ai.model_select",
            validate_model_select_params as SchemaFn,
            validate_model_select_result as SchemaFn,
        )),
        "ai.model_fallback" => Some((
            "ai.model_fallback",
            validate_model_fallback_params as SchemaFn,
            validate_model_fallback_result as SchemaFn,
        )),
        "ai.model_cost" => Some((
            "ai.model_cost",
            validate_model_cost_params as SchemaFn,
            validate_model_cost_result as SchemaFn,
        )),
        "ai.tool_dispatch" => Some((
            "ai.tool_dispatch",
            validate_tool_dispatch_params as SchemaFn,
            validate_tool_dispatch_result as SchemaFn,
        )),
        "ai.context_read" => Some((
            "ai.context_read",
            validate_context_read_params as SchemaFn,
            validate_context_read_result as SchemaFn,
        )),
        "ai.extension_manifest" => Some((
            "ai.extension_manifest",
            validate_extension_manifest_params as SchemaFn,
            validate_extension_manifest_result as SchemaFn,
        )),
        "ai.extension_contribute" => Some((
            "ai.extension_contribute",
            validate_extension_contribute_params as SchemaFn,
            validate_extension_contribute_result as SchemaFn,
        )),
        "ai.extension_activate" => Some((
            "ai.extension_activate",
            validate_extension_activate_params as SchemaFn,
            validate_extension_activate_result as SchemaFn,
        )),
        "ai.cache_hint" => Some((
            "ai.cache_hint",
            validate_cache_hint_params as SchemaFn,
            validate_cache_hint_result as SchemaFn,
        )),
        "ai.mcp_pin" => Some((
            "ai.mcp_pin",
            validate_mcp_pin_params as SchemaFn,
            validate_mcp_pin_result as SchemaFn,
        )),
        "ai.mcp_snapshot" => Some((
            "ai.mcp_snapshot",
            validate_mcp_snapshot_params as SchemaFn,
            validate_mcp_snapshot_result as SchemaFn,
        )),
        _ => None,
    }
}

fn parse_top(bytes: &[u8], what: &str) -> Result<Vec<(String, JVal)>, IpcError> {
    let mut p = Parser { b: bytes, pos: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.pos != bytes.len() {
        return Err(invalid_frame("json: trailing bytes"));
    }
    match v {
        JVal::Obj(fields) => Ok(fields),
        _ => Err(IpcError::InvalidRequest {
            reason: format!("{what} must be a JSON object"),
        }),
    }
}

/// Validate `params` bytes for one `ai.*` method per its canonical schema.
///
/// Runs the canonical `params` rules first (frame bound, UTF-8, depth
/// `<= 32`, no ambient authority), then the per-method field schema.
/// Unknown methods refuse [`IpcError::NotFound`] (same as
/// `authorize_method`); unknown fields refuse [`IpcError::InvalidRequest`].
///
/// An empty body is accepted only by fieldless methods (`ai.provider_list`,
/// `ai.mcp_pin`, `ai.mcp_snapshot`); every other method refuses it through
/// its missing-required-field arm.
///
/// # Errors
///
/// - `NotFound` for an unregistered method.
/// - Canonical classes (`PayloadTooLarge`, `InvalidFrame`,
///   `InvalidRequest`) from the byte layer.
/// - `InvalidRequest` for unknown/duplicate fields, missing required
///   fields, wrong types, or closed-vocabulary violations.
/// - `LimitExceeded` for over-bound strings and counts.
pub fn validate_ai_params(method: &str, params: &[u8]) -> Result<(), IpcError> {
    let (name, params_fn, _) = ai_handlers(method).ok_or_else(|| IpcError::NotFound {
        reason: format!("unknown method '{method}'"),
    })?;
    validate_params_json(params)?;
    // POLICY (CTX-0011): empty body parses as no fields (fieldless methods
    // accept; the rest refuse via missing-required).
    let owned;
    let slice: &[(String, JVal)] = if params.is_empty() {
        &[]
    } else {
        owned = parse_top(params, "params")?;
        &owned
    };
    params_fn(&Fields {
        method: name,
        what: "params",
        fields: slice,
    })
}

/// Validate `result` bytes for one `ai.*` method per its canonical schema.
///
/// Same layering as [`validate_ai_params`] with the `result` byte rules.
/// `ai.extension_activate` has no success shape and refuses every body
/// under the deny-all posture.
///
/// # Errors
///
/// Same classes as [`validate_ai_params`].
pub fn validate_ai_result(method: &str, result: &[u8]) -> Result<(), IpcError> {
    let (name, _, result_fn) = ai_handlers(method).ok_or_else(|| IpcError::NotFound {
        reason: format!("unknown method '{method}'"),
    })?;
    validate_result_json(result)?;
    // POLICY (CTX-0011): an empty result body is never a result (every
    // method requires a result object); refused as missing rather than
    // parsed.
    if result.is_empty() {
        return Err(IpcError::InvalidRequest {
            reason: format!("{name} result: missing result object"),
        });
    }
    let owned = parse_top(result, "result")?;
    result_fn(&Fields {
        method: name,
        what: "result",
        fields: &owned,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(method: &str, body: &str) -> Result<(), IpcError> {
        validate_ai_params(method, body.as_bytes())
    }

    fn result(method: &str, body: &str) -> Result<(), IpcError> {
        validate_ai_result(method, body.as_bytes())
    }

    fn is_invalid_request(r: &Result<(), IpcError>) -> bool {
        matches!(r, Err(IpcError::InvalidRequest { .. }))
    }

    // ── framework ──

    #[test]
    fn unknown_method_is_not_found() {
        assert!(matches!(
            validate_ai_params("ai.evil", b"{}"),
            Err(IpcError::NotFound { .. })
        ));
        assert!(matches!(
            validate_ai_result("ai.evil", b"{}"),
            Err(IpcError::NotFound { .. })
        ));
    }

    #[test]
    fn non_object_top_refused() {
        assert!(is_invalid_request(&params("ai.provider_list", "[1,2]")));
        assert!(is_invalid_request(&params("ai.provider_list", "\"x\"")));
        assert!(is_invalid_request(&result("ai.provider_list", "42")));
    }

    #[test]
    fn trailing_bytes_refused() {
        assert!(matches!(
            params("ai.provider_list", "{} trailing"),
            Err(IpcError::InvalidFrame { .. })
        ));
    }

    #[test]
    fn duplicate_key_refused() {
        assert!(is_invalid_request(&params(
            "ai.model_cost",
            r#"{"input_tokens":1,"input_tokens":2,"output_tokens":0,"input_weight":0,"output_weight":0}"#
        )));
    }

    #[test]
    fn depth_33_refused_before_schema_shape() {
        // 32 nested arrays inside the params object reach depth 33 total:
        // the canonical pre-check fires first (PayloadTooLarge), proving
        // schema validation runs above the byte layer, never instead of it.
        let deep = format!("{{\"error\": {} }}", "[".repeat(32) + &"]".repeat(32));
        assert!(matches!(
            params("ai.model_fallback", &deep),
            Err(IpcError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn depth_32_passes_canonical_then_fails_shape() {
        // 31 nested arrays inside the params object reach depth 32 total:
        // clears the byte layer and reaches the schema, where the wrong
        // type refuses with InvalidRequest (not a depth error).
        let at_cap = format!("{{\"error\": {} }}", "[".repeat(31) + &"]".repeat(31));
        assert!(is_invalid_request(&params("ai.model_fallback", &at_cap)));
    }

    // ── ai.provider_list ──

    #[test]
    fn provider_list_params_accept_empty_and_braces() {
        assert!(validate_ai_params("ai.provider_list", b"").is_ok());
        assert!(params("ai.provider_list", "{}").is_ok());
    }

    #[test]
    fn provider_list_params_refuse_unknown() {
        // The reserved scoped variant must never cross (MP-4 deferred).
        assert!(is_invalid_request(&params(
            "ai.provider_list",
            r#"{"caller_scope":"admin"}"#
        )));
        assert!(is_invalid_request(&params(
            "ai.provider_list",
            r#"{"scope":"x"}"#
        )));
    }

    const LIST_RESULT: &str = r#"{"models":[{"provider_id":"p1","name":"m1","capabilities":["text","tool_use"],"context_window_tokens":8192,"input_cost_weight":1,"output_cost_weight":2}]}"#;

    #[test]
    fn provider_list_result_accept() {
        assert!(result("ai.provider_list", LIST_RESULT).is_ok());
        assert!(result("ai.provider_list", r#"{"models":[]}"#).is_ok());
    }

    #[test]
    fn provider_list_result_refusals() {
        assert!(is_invalid_request(&result(
            "ai.provider_list",
            r#"{"models":[] ,"extra":1}"#
        )));
        let long = format!(
            "{{\"models\":[{{\"provider_id\":\"{}\",\"name\":\"m\",\"capabilities\":[\"text\"],\"context_window_tokens\":0,\"input_cost_weight\":0,\"output_cost_weight\":0}}]}}",
            "p".repeat(65)
        );
        assert!(matches!(
            result("ai.provider_list", &long),
            Err(IpcError::LimitExceeded { .. })
        ));
        assert!(is_invalid_request(&result("ai.provider_list", "{}")));
        assert!(is_invalid_request(&result(
            "ai.provider_list",
            r#"{"models":[{"provider_id":"p","name":"m","capabilities":["telepathy"],"context_window_tokens":0,"input_cost_weight":0,"output_cost_weight":0}]}"#
        )));
        assert!(is_invalid_request(&result(
            "ai.provider_list",
            r#"{"models":[{"provider_id":"p","name":"m","capabilities":[],"context_window_tokens":0,"input_cost_weight":0,"output_cost_weight":0}]}"#
        )));
        assert!(is_invalid_request(&result(
            "ai.provider_list",
            r#"{"models":[{"provider_id":"p","name":"m","capabilities":["text"],"context_window_tokens":-1,"input_cost_weight":0,"output_cost_weight":0}]}"#
        )));
    }

    // ── ai.provider_complete ──

    const COMPLETE_PARAMS: &str = r#"{"model":{"provider_id":"p1","model":"m1"},"messages":[{"role":"user","content":"hi"}],"budget_bytes":1024,"timeout_ms":5000,"now_ms":1700000000000}"#;

    #[test]
    fn provider_complete_params_accept_and_defaults() {
        assert!(params("ai.provider_complete", COMPLETE_PARAMS).is_ok());
        // Optional: context_refs, tools, sampling default out.
        let full = r#"{"model":{"provider_id":"p1","model":"m1"},"messages":[],"context_refs":["a_b-1"],"tools":["fetch"],"budget_bytes":0,"timeout_ms":30000,"now_ms":0,"sampling":"declared"}"#;
        assert!(params("ai.provider_complete", full).is_ok());
    }

    #[test]
    fn provider_complete_params_refusals() {
        assert!(is_invalid_request(&params(
            "ai.provider_complete",
            r#"{"model":{"provider_id":"p1","model":"m1"},"messages":[],"budget_bytes":0,"timeout_ms":5,"now_ms":0,"zzz":1}"#
        )));
        let big = format!(
            "{{\"model\":{{\"provider_id\":\"p\",\"model\":\"m\"}},\"messages\":[{{\"role\":\"user\",\"content\":\"{}\"}}],\"budget_bytes\":99999999,\"timeout_ms\":5,\"now_ms\":0}}",
            "c".repeat(17 * 1024)
        );
        assert!(matches!(
            params("ai.provider_complete", &big),
            Err(IpcError::LimitExceeded { .. })
        ));
        assert!(is_invalid_request(&params(
            "ai.provider_complete",
            r#"{"messages":[],"budget_bytes":0,"timeout_ms":5,"now_ms":0}"#
        )));
        assert!(is_invalid_request(&params(
            "ai.provider_complete",
            &COMPLETE_PARAMS.replace("\"timeout_ms\":5000", "\"timeout_ms\":30001")
        )));
        assert!(is_invalid_request(&params(
            "ai.provider_complete",
            &COMPLETE_PARAMS.replace("\"timeout_ms\":5000", "\"timeout_ms\":0")
        )));
        assert!(is_invalid_request(&params(
            "ai.provider_complete",
            &COMPLETE_PARAMS.replace('}', ",\"sampling\":\"maybe\"}")
        )));
        // Budget below message total refuses.
        assert!(matches!(
            params(
                "ai.provider_complete",
                &COMPLETE_PARAMS.replace("\"budget_bytes\":1024", "\"budget_bytes\":1")
            ),
            Err(IpcError::LimitExceeded { .. })
        ));
    }

    const COMPLETE_RESULT: &str = r#"{"text":"done","tool_calls":[{"name":"fetch","arguments":"{}"}],"usage":{"input_tokens":10,"output_tokens":5,"cached_tokens":0,"cache_write_tokens":0},"latency_ms":120}"#;

    #[test]
    fn provider_complete_result_accept_and_refusals() {
        assert!(result("ai.provider_complete", COMPLETE_RESULT).is_ok());
        assert!(is_invalid_request(&result(
            "ai.provider_complete",
            &COMPLETE_RESULT.replace("\"latency_ms\":120", "\"latency_ms\":120,\"zzz\":1")
        )));
        assert!(is_invalid_request(&result(
            "ai.provider_complete",
            r#"{"text":"t","tool_calls":[],"usage":{"input_tokens":0,"output_tokens":0,"cached_tokens":0,"cache_write_tokens":0}}"#
        )));
        assert!(is_invalid_request(&result(
            "ai.provider_complete",
            r#"{"text":"done","tool_calls":[],"usage":{"input_tokens":1.5,"output_tokens":5,"cached_tokens":0,"cache_write_tokens":0},"latency_ms":120}"#
        )));
    }

    // ── ai.model_select ──

    #[test]
    fn model_select_params_accept() {
        assert!(params("ai.model_select", r#"{"required":["text"]}"#).is_ok());
        assert!(params(
            "ai.model_select",
            r#"{"required":["text","reasoning"],"alias":"fast","min_context_window_tokens":4096,"max_cost_weight":3}"#
        )
        .is_ok());
    }

    #[test]
    fn model_select_params_refusals() {
        assert!(is_invalid_request(&params(
            "ai.model_select",
            r#"{"required":["text"],"zzz":1}"#
        )));
        let long = format!(
            "{{\"required\":[\"text\"],\"alias\":\"{}\"}}",
            "a".repeat(129)
        );
        assert!(matches!(
            params("ai.model_select", &long),
            Err(IpcError::LimitExceeded { .. })
        ));
        // Alias at exactly 128 passes.
        let at_cap = format!(
            "{{\"required\":[\"text\"],\"alias\":\"{}\"}}",
            "a".repeat(128)
        );
        assert!(params("ai.model_select", &at_cap).is_ok());
        assert!(is_invalid_request(&params("ai.model_select", "{}")));
        assert!(is_invalid_request(&params(
            "ai.model_select",
            r#"{"required":[]}"#
        )));
        assert!(is_invalid_request(&params(
            "ai.model_select",
            r#"{"required":["text"],"min_context_window_tokens":"big"}"#
        )));
    }

    #[test]
    fn model_select_result_accept_and_refusals() {
        let selected = r#"{"status":"selected","chain":[{"provider_id":"p","name":"m","capabilities":["text"],"context_window_tokens":0,"input_cost_weight":0,"output_cost_weight":0}]}"#;
        assert!(result("ai.model_select", selected).is_ok());
        assert!(
            result(
                "ai.model_select",
                r#"{"status":"failed","error":"no candidate"}"#
            )
            .is_ok()
        );
        assert!(is_invalid_request(&result(
            "ai.model_select",
            r#"{"status":"failed","error":"x","zzz":1}"#
        )));
        assert!(is_invalid_request(&result(
            "ai.model_select",
            r#"{"status":"maybe"}"#
        )));
        assert!(is_invalid_request(&result(
            "ai.model_select",
            r#"{"chain":[]}"#
        )));
        // Selected must not carry error; failed must not carry chain.
        assert!(is_invalid_request(&result(
            "ai.model_select",
            r#"{"status":"selected","chain":[],"error":"x"}"#
        )));
        assert!(is_invalid_request(&result(
            "ai.model_select",
            r#"{"status":"failed","chain":[],"error":"x"}"#
        )));
    }

    // ── ai.model_fallback ──

    #[test]
    fn model_fallback_accept_and_refusals() {
        assert!(params("ai.model_fallback", r#"{"error":"transport"}"#).is_ok());
        assert!(
            params(
                "ai.model_fallback",
                r#"{"error":"invalid_sampling","detail":"ranges"}"#
            )
            .is_ok()
        );
        assert!(result("ai.model_fallback", r#"{"directive":"advance"}"#).is_ok());
        assert!(is_invalid_request(&params(
            "ai.model_fallback",
            r#"{"error":"transport","zzz":1}"#
        )));
        assert!(is_invalid_request(&params(
            "ai.model_fallback",
            r#"{"error":"panic"}"#
        )));
        assert!(is_invalid_request(&params("ai.model_fallback", "{}")));
        let long = format!("{{\"error\":\"auth\",\"detail\":\"{}\"}}", "d".repeat(513));
        assert!(matches!(
            params("ai.model_fallback", &long),
            Err(IpcError::LimitExceeded { .. })
        ));
        assert!(is_invalid_request(&result(
            "ai.model_fallback",
            r#"{"directive":"retry"}"#
        )));
    }

    // ── ai.model_cost ──

    #[test]
    fn model_cost_accept_and_refusals() {
        assert!(
            params(
                "ai.model_cost",
                r#"{"input_tokens":100,"output_tokens":20,"input_weight":0,"output_weight":2}"#
            )
            .is_ok()
        );
        assert!(result(
            "ai.model_cost",
            r#"{"input_tokens":100,"output_tokens":20,"input_weight":0,"output_weight":2,"cost":140}"#
        )
        .is_ok());
        assert!(is_invalid_request(&params(
            "ai.model_cost",
            r#"{"input_tokens":100,"output_tokens":20,"input_weight":0,"output_weight":2,"zzz":0}"#
        )));
        assert!(is_invalid_request(&params(
            "ai.model_cost",
            r#"{"input_tokens":100,"output_tokens":20,"input_weight":0}"#
        )));
        assert!(is_invalid_request(&params(
            "ai.model_cost",
            r#"{"input_tokens":-3,"output_tokens":20,"input_weight":0,"output_weight":2}"#
        )));
        assert!(is_invalid_request(&result(
            "ai.model_cost",
            r#"{"input_tokens":100,"output_tokens":20,"input_weight":0,"output_weight":2,"cost":"lots"}"#
        )));
    }

    // ── ai.tool_dispatch ──

    const DISPATCH_PARAMS: &str = r#"{"tool":"fetch","args_digest":123,"caller":{"agent_instance_id":7,"session_id":9,"level":"own"},"now_ms":1700000000000}"#;

    #[test]
    fn tool_dispatch_params_accept() {
        assert!(params("ai.tool_dispatch", DISPATCH_PARAMS).is_ok());
        // Explicit empty allow-set is valid (narrows everything away).
        assert!(params(
            "ai.tool_dispatch",
            r#"{"tool":"fetch","args_digest":123,"caller":{"agent_instance_id":7,"session_id":9,"level":"own"},"allowed":[],"now_ms":1700000000000}"#
        )
        .is_ok());
    }

    #[test]
    fn tool_dispatch_params_refusals() {
        assert!(is_invalid_request(&params(
            "ai.tool_dispatch",
            r#"{"tool":"fetch","args_digest":123,"caller":{"agent_instance_id":7,"session_id":9,"level":"own"},"now_ms":1700000000000,"zzz":1}"#
        )));
        let long = format!(
            "{{\"tool\":\"{}\",\"args_digest\":1,\"caller\":{{\"agent_instance_id\":1,\"session_id\":1,\"level\":\"inspect\"}},\"now_ms\":0}}",
            "t".repeat(65)
        );
        assert!(matches!(
            params("ai.tool_dispatch", &long),
            Err(IpcError::LimitExceeded { .. })
        ));
        assert!(is_invalid_request(&params(
            "ai.tool_dispatch",
            r#"{"tool":"fetch"}"#
        )));
        assert!(is_invalid_request(&params(
            "ai.tool_dispatch",
            &DISPATCH_PARAMS.replace("\"own\"", "\"root\"")
        )));
        let many = format!(
            "{{\"tool\":\"t\",\"args_digest\":1,\"caller\":{{\"agent_instance_id\":1,\"session_id\":1,\"level\":\"inspect\"}},\"allowed\":[{}],\"now_ms\":0}}",
            (0..33)
                .map(|i| format!("\"t{i}\""))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(matches!(
            params("ai.tool_dispatch", &many),
            Err(IpcError::LimitExceeded { .. })
        ));
    }

    const DISPATCH_RESULT: &str = r#"{"status":"success","result_disposition":"accepted","reason":"","usage":{"execution_id":3,"tool":"fetch","args_digest":123,"occurred_at_ms":1700000000001}}"#;

    #[test]
    fn tool_dispatch_result_accept_and_refusals() {
        assert!(result("ai.tool_dispatch", DISPATCH_RESULT).is_ok());
        assert!(is_invalid_request(&result(
            "ai.tool_dispatch",
            &DISPATCH_RESULT.replace("\"accepted\"", "\"accepted\",\"zzz\":1")
        )));
        assert!(is_invalid_request(&result(
            "ai.tool_dispatch",
            &DISPATCH_RESULT.replace("\"success\"", "\"successful\"")
        )));
        assert!(is_invalid_request(&result(
            "ai.tool_dispatch",
            r#"{"status":"success","result_disposition":"accepted","usage":{"execution_id":3,"tool":"fetch","args_digest":1,"occurred_at_ms":0}}"#
        )));
    }

    // ── ai.context_read ──

    const READ_PARAMS: &str = r#"{"scopes":["a_b-1"],"request":{"current_generation":42}}"#;

    #[test]
    fn context_read_params_accept() {
        assert!(params("ai.context_read", READ_PARAMS).is_ok());
        assert!(params(
            "ai.context_read",
            r#"{"scopes":["a"],"request":{"max_tokens":100,"max_bytes":4096,"current_generation":1},"detail":"full"}"#
        )
        .is_ok());
    }

    #[test]
    fn context_read_params_refusals() {
        assert!(is_invalid_request(&params(
            "ai.context_read",
            r#"{"scopes":["a"],"request":{"current_generation":1},"zzz":1}"#
        )));
        let long = format!(
            "{{\"scopes\":[\"{}\"],\"request\":{{\"current_generation\":1}}}}",
            "s".repeat(65)
        );
        assert!(matches!(
            params("ai.context_read", &long),
            Err(IpcError::LimitExceeded { .. })
        ));
        assert!(is_invalid_request(&params(
            "ai.context_read",
            r#"{"request":{"current_generation":1}}"#
        )));
        assert!(is_invalid_request(&params(
            "ai.context_read",
            r#"{"scopes":[],"request":{"current_generation":1}}"#
        )));
        assert!(is_invalid_request(&params(
            "ai.context_read",
            r#"{"scopes":["a"],"request":{"current_generation":1},"detail":"verbose"}"#
        )));
    }

    const READ_RESULT: &str = r#"{"current_generation":42,"records":[{"id":"r1","provider":"p1","summary":"s","content":{"kind":"inline","body":"hello"},"is_untrusted_surface":true}],"context_refs":[],"omitted_ids":[],"pruned_ids":[],"externalized":0,"truncated_bytes":0,"truncated_tokens_estimate":0,"truncated_providers":[],"budget_bytes":4096,"absences":[{"reference":"r9","absence":"missing"}]}"#;

    #[test]
    fn context_read_result_accept_and_refusals() {
        assert!(result("ai.context_read", READ_RESULT).is_ok());
        assert!(is_invalid_request(&result(
            "ai.context_read",
            &READ_RESULT.replace("\"budget_bytes\":4096", "\"budget_bytes\":4096,\"zzz\":1")
        )));
        assert!(is_invalid_request(&result(
            "ai.context_read",
            &READ_RESULT.replace("\"current_generation\":42,", "")
        )));
        // Inline content must not carry a reference arm.
        assert!(is_invalid_request(&result(
            "ai.context_read",
            &READ_RESULT.replace(
                "\"body\":\"hello\"",
                "\"body\":\"hello\",\"reference\":\"r1\""
            )
        )));
        assert!(is_invalid_request(&result(
            "ai.context_read",
            &READ_RESULT.replace("\"missing\"", "\"gone\"")
        )));
    }

    // ── ai.extension_manifest ──

    const MANIFEST_PARAMS: &str =
        r#"{"manifest":{"name":"ext","version":"1.0","host":">=0.1","points":["tool","ui"]}}"#;

    #[test]
    fn extension_manifest_accept_and_refusals() {
        assert!(params("ai.extension_manifest", MANIFEST_PARAMS).is_ok());
        assert!(result("ai.extension_manifest", MANIFEST_PARAMS).is_ok());
        assert!(is_invalid_request(&params(
            "ai.extension_manifest",
            r#"{"manifest":{"name":"e","version":"1","host":"h","points":[]},"zzz":1}"#
        )));
        let long = format!(
            "{{\"manifest\":{{\"name\":\"{}\",\"version\":\"1\",\"host\":\"h\",\"points\":[]}}}}",
            "n".repeat(513)
        );
        assert!(matches!(
            params("ai.extension_manifest", &long),
            Err(IpcError::LimitExceeded { .. })
        ));
        assert!(is_invalid_request(&params("ai.extension_manifest", "{}")));
        assert!(is_invalid_request(&params(
            "ai.extension_manifest",
            r#"{"manifest":{"name":"e","version":"1","host":"h","points":["widget"]}}"#
        )));
    }

    // ── ai.extension_contribute ──

    #[test]
    fn extension_contribute_accept_and_refusals() {
        assert!(
            params(
                "ai.extension_contribute",
                r#"{"point":"tool","value":"read-only fetch"}"#
            )
            .is_ok()
        );
        assert!(
            result(
                "ai.extension_contribute",
                r#"{"point":"ui","value":"panel"}"#
            )
            .is_ok()
        );
        assert!(is_invalid_request(&params(
            "ai.extension_contribute",
            r#"{"point":"tool","value":"v","zzz":1}"#
        )));
        let long = format!("{{\"point\":\"tool\",\"value\":\"{}\"}}", "v".repeat(513));
        assert!(matches!(
            params("ai.extension_contribute", &long),
            Err(IpcError::LimitExceeded { .. })
        ));
        assert!(is_invalid_request(&params(
            "ai.extension_contribute",
            r#"{"value":"v"}"#
        )));
        assert!(is_invalid_request(&params(
            "ai.extension_contribute",
            r#"{"point":"widget","value":"v"}"#
        )));
    }

    // ── ai.extension_activate ──

    #[test]
    fn extension_activate_params_accept_and_refusals() {
        assert!(params("ai.extension_activate", r#"{"point":"tool"}"#).is_ok());
        assert!(
            params(
                "ai.extension_activate",
                r#"{"point":"future-point","enabled":["tool"]}"#
            )
            .is_ok()
        );
        assert!(is_invalid_request(&params(
            "ai.extension_activate",
            r#"{"point":"tool","zzz":1}"#
        )));
        assert!(is_invalid_request(&params(
            "ai.extension_activate",
            r#"{"point":""}"#
        )));
        assert!(is_invalid_request(&params("ai.extension_activate", "{}")));
        let long = format!("{{\"point\":\"{}\"}}", "p".repeat(129));
        assert!(matches!(
            params("ai.extension_activate", &long),
            Err(IpcError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn extension_activate_result_always_refused() {
        assert!(is_invalid_request(&result("ai.extension_activate", "{}")));
        assert!(is_invalid_request(&result(
            "ai.extension_activate",
            r#"{"ok":true}"#
        )));
        assert!(matches!(
            validate_ai_result("ai.extension_activate", b""),
            Err(IpcError::InvalidRequest { .. })
        ));
    }

    // ── ai.cache_hint ──

    const HINT_PARAMS: &str = r#"{"key":{"provider_id":"p1","model_id":"m1","scope":"session","stable_prefix_hash":99,"prefix_len":128},"ask_scope":"session","fingerprint":{"digest":7,"input_len":1024}}"#;

    #[test]
    fn cache_hint_params_accept_and_refusals() {
        assert!(params("ai.cache_hint", HINT_PARAMS).is_ok());
        assert!(is_invalid_request(&params(
            "ai.cache_hint",
            &HINT_PARAMS.replace("\"input_len\":1024", "\"input_len\":1024,\"zzz\":1")
        )));
        let long = format!(
            "{{\"key\":{{\"provider_id\":\"{}\",\"model_id\":\"m\",\"scope\":\"session\",\"stable_prefix_hash\":1,\"prefix_len\":1}},\"ask_scope\":\"session\",\"fingerprint\":{{\"digest\":1,\"input_len\":1}}}}",
            "p".repeat(65)
        );
        assert!(matches!(
            params("ai.cache_hint", &long),
            Err(IpcError::LimitExceeded { .. })
        ));
        assert!(is_invalid_request(&params(
            "ai.cache_hint",
            r#"{"scope":"session"}"#
        )));
        assert!(is_invalid_request(&params(
            "ai.cache_hint",
            &HINT_PARAMS.replace("\"ask_scope\":\"session\"", "\"ask_scope\":\"global\"")
        )));
        // Scope mismatch between key and request refuses.
        assert!(is_invalid_request(&params(
            "ai.cache_hint",
            &HINT_PARAMS.replacen("\"scope\":\"session\"", "\"scope\":\"turn\"", 1)
        )));
    }

    #[test]
    fn cache_hint_result_accept_and_refusals() {
        assert!(result(
            "ai.cache_hint",
            r#"{"key":{"provider_id":"p1","model_id":"m1","scope":"session","stable_prefix_hash":99,"prefix_len":128},"hit":true}"#
        )
        .is_ok());
        assert!(is_invalid_request(&result(
            "ai.cache_hint",
            r#"{"key":{"provider_id":"p","model_id":"m","scope":"turn","stable_prefix_hash":1,"prefix_len":1},"hit":"yes"}"#
        )));
    }

    // ── ai.mcp_pin ──

    #[test]
    fn mcp_pin_params_accept_empty_and_refuse_unknown() {
        assert!(validate_ai_params("ai.mcp_pin", b"").is_ok());
        assert!(params("ai.mcp_pin", "{}").is_ok());
        assert!(is_invalid_request(&params("ai.mcp_pin", r#"{"pin":{}}"#)));
    }

    const PIN_RESULT: &str = r#"{"protocol_version":"2025-11-25","tools_supported":true,"tools_shape":{"kind":"object","list_changed":true}}"#;

    #[test]
    fn mcp_pin_result_accept_and_refusals() {
        assert!(result("ai.mcp_pin", PIN_RESULT).is_ok());
        assert!(result(
            "ai.mcp_pin",
            r#"{"protocol_version":"2025-11-25","tools_supported":true,"tools_shape":{"kind":"bool_true"}}"#
        )
        .is_ok());
        // Absent and null list_changed both mean None.
        assert!(result(
            "ai.mcp_pin",
            r#"{"protocol_version":"v","tools_supported":false,"tools_shape":{"kind":"object"}}"#
        )
        .is_ok());
        assert!(is_invalid_request(&result(
            "ai.mcp_pin",
            &PIN_RESULT.replace("\"list_changed\":true", "\"list_changed\":true,\"zzz\":1")
        )));
        let long = format!(
            "{{\"protocol_version\":\"{}\",\"tools_supported\":true,\"tools_shape\":{{\"kind\":\"bool_true\"}}}}",
            "v".repeat(129)
        );
        assert!(matches!(
            result("ai.mcp_pin", &long),
            Err(IpcError::LimitExceeded { .. })
        ));
        assert!(is_invalid_request(&result(
            "ai.mcp_pin",
            r#"{"protocol_version":"v"}"#
        )));
        assert!(is_invalid_request(&result(
            "ai.mcp_pin",
            &PIN_RESULT.replace("\"list_changed\":true", "\"list_changed\":\"yes\"")
        )));
    }

    // ── ai.mcp_snapshot ──

    #[test]
    fn mcp_snapshot_params_accept_empty_and_refuse_unknown() {
        assert!(validate_ai_params("ai.mcp_snapshot", b"").is_ok());
        assert!(params("ai.mcp_snapshot", "{}").is_ok());
        assert!(is_invalid_request(&params(
            "ai.mcp_snapshot",
            r#"{"since":3}"#
        )));
    }

    const SNAPSHOT_RESULT: &str =
        r#"{"entries":[{"name":"fetch","digest":123}],"list_version":7,"list_stale":false}"#;

    #[test]
    fn mcp_snapshot_result_accept_and_refusals() {
        assert!(result("ai.mcp_snapshot", SNAPSHOT_RESULT).is_ok());
        assert!(is_invalid_request(&result(
            "ai.mcp_snapshot",
            &SNAPSHOT_RESULT.replace("\"list_version\":7", "\"list_version\":7,\"zzz\":1")
        )));
        let long = format!(
            "{{\"entries\":[{{\"name\":\"{}\",\"digest\":1}}],\"list_version\":1,\"list_stale\":false}}",
            "n".repeat(65)
        );
        assert!(matches!(
            result("ai.mcp_snapshot", &long),
            Err(IpcError::LimitExceeded { .. })
        ));
        assert!(is_invalid_request(&result(
            "ai.mcp_snapshot",
            r#"{"entries":[]}"#
        )));
        assert!(is_invalid_request(&result(
            "ai.mcp_snapshot",
            &SNAPSHOT_RESULT.replace("\"digest\":123", "\"digest\":-1")
        )));
    }
}
