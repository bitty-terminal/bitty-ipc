//! Provider-routing projection DTOs and exact canonical byte encoding.
//!
//! The canonical profile is part of the accepted provider/routing binding
//! contract, not an incidental serializer choice:
//!
//! - exact UTF-8 JSON, no insignificant whitespace;
//! - top-level order `domain`, `providers`; provider order `id`, `models`;
//!   model order `name`, `capabilities`, `context_window_tokens`,
//!   `input_cost_weight`, `output_cost_weight`;
//! - providers sorted by `id`, models by `name`, capabilities by label,
//!   ascending bytewise over UTF-8;
//! - non-ASCII scalars are emitted raw; `"`, `\`, and U+0000..=U+001F use the
//!   shortest canonical escape;
//! - the three numeric fields are unsigned base-10 integers in `u32` range;
//! - the digest is lowercase hexadecimal SHA-256 over exactly these bytes.
//!
//! The rules and byte output intentionally match the reviewed AI-0324/AI-0330
//! baseline. `0` keeps the registry meanings of unknown context window and
//! uncalibrated cost weight.

use std::cmp::Ordering;

use crate::error::IpcError;
use crate::wire::validate_json_depth;

use super::error::{PayloadError, TextViolation};
use super::ids::Digest;
use super::{
    CONTROL_CAPABILITIES_MAX, CONTROL_JSON_DEPTH_MAX, CONTROL_MODELS_MAX,
    CONTROL_PAYLOAD_MAX_BYTES, CONTROL_PROVIDER_GROUPS_MAX, CONTROL_STRING_MAX_BYTES,
};

/// Exact canonical domain string for this projection.
pub const PROVIDER_ROUTING_DOMAIN: &str = "provider-routing";

/// Closed capability vocabulary in canonical label order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Audio input.
    AudioInput,
    /// Audio output.
    AudioOutput,
    /// Image input.
    ImageInput,
    /// Reasoning.
    Reasoning,
    /// Streaming.
    Streaming,
    /// Text.
    Text,
    /// Tool use.
    ToolUse,
    /// Video input.
    VideoInput,
}

impl Capability {
    /// All labels in canonical bytewise order.
    pub const ALL: [Self; CONTROL_CAPABILITIES_MAX] = [
        Self::AudioInput,
        Self::AudioOutput,
        Self::ImageInput,
        Self::Reasoning,
        Self::Streaming,
        Self::Text,
        Self::ToolUse,
        Self::VideoInput,
    ];

    /// Exact canonical label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Streaming => "streaming",
            Self::ToolUse => "tool_use",
            Self::ImageInput => "image_input",
            Self::AudioInput => "audio_input",
            Self::AudioOutput => "audio_output",
            Self::VideoInput => "video_input",
            Self::Reasoning => "reasoning",
        }
    }

    /// Parse one exact canonical label.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "text" => Some(Self::Text),
            "streaming" => Some(Self::Streaming),
            "tool_use" => Some(Self::ToolUse),
            "image_input" => Some(Self::ImageInput),
            "audio_input" => Some(Self::AudioInput),
            "audio_output" => Some(Self::AudioOutput),
            "video_input" => Some(Self::VideoInput),
            "reasoning" => Some(Self::Reasoning),
            _ => None,
        }
    }
}

impl Ord for Capability {
    fn cmp(&self, other: &Self) -> Ordering {
        self.label().cmp(other.label())
    }
}

impl PartialOrd for Capability {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// One model entry in the canonical projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelEntry {
    name: String,
    capabilities: Vec<Capability>,
    context_window_tokens: u32,
    input_cost_weight: u32,
    output_cost_weight: u32,
}

impl ModelEntry {
    /// Construct a model entry with sorted, unique capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError::InvalidText`] for an empty, overlong, or
    /// control-bearing name; [`PayloadError::EmptyCapabilityGroup`] when no
    /// label is present; [`PayloadError::TooManyCapabilities`] above the
    /// named bound; or [`PayloadError::DuplicateCapability`] for a repeated
    /// label.
    pub fn new(
        name: impl Into<String>,
        capabilities: Vec<Capability>,
        context_window_tokens: u32,
        input_cost_weight: u32,
        output_cost_weight: u32,
    ) -> Result<Self, PayloadError> {
        let name = name.into();
        check_text("model.name", &name)?;
        let mut capabilities = capabilities;
        if capabilities.is_empty() {
            return Err(PayloadError::EmptyCapabilityGroup);
        }
        if capabilities.len() > CONTROL_CAPABILITIES_MAX {
            return Err(PayloadError::TooManyCapabilities {
                actual: capabilities.len(),
                limit: CONTROL_CAPABILITIES_MAX,
            });
        }
        capabilities.sort_unstable();
        if capabilities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(PayloadError::DuplicateCapability);
        }
        Ok(Self {
            name,
            capabilities,
            context_window_tokens,
            input_cost_weight,
            output_cost_weight,
        })
    }

    /// Bounded model name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Sorted unique capability labels.
    #[must_use]
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Registry context window, `0` meaning unknown.
    #[must_use]
    pub const fn context_window_tokens(&self) -> u32 {
        self.context_window_tokens
    }

    /// Relative input cost weight, `0` meaning uncalibrated.
    #[must_use]
    pub const fn input_cost_weight(&self) -> u32 {
        self.input_cost_weight
    }

    /// Relative output cost weight, `0` meaning uncalibrated.
    #[must_use]
    pub const fn output_cost_weight(&self) -> u32 {
        self.output_cost_weight
    }
}

/// One provider group in the canonical projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEntry {
    id: String,
    models: Vec<ModelEntry>,
}

impl ProviderEntry {
    /// Construct a provider group with sorted, unique model names.
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError::InvalidText`] for an invalid identity,
    /// [`PayloadError::EmptyProviderGroup`] when `models` is empty, or
    /// [`PayloadError::DuplicateModel`] for a repeated model name.
    pub fn new(id: impl Into<String>, models: Vec<ModelEntry>) -> Result<Self, PayloadError> {
        let id = id.into();
        check_text("provider.id", &id)?;
        if models.is_empty() {
            return Err(PayloadError::EmptyProviderGroup);
        }
        let mut models = models;
        models.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        if models.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return Err(PayloadError::DuplicateModel);
        }
        Ok(Self { id, models })
    }

    /// Bounded provider identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Sorted unique models.
    #[must_use]
    pub fn models(&self) -> &[ModelEntry] {
        &self.models
    }
}

/// Canonical provider-routing projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRoutingProjection {
    providers: Vec<ProviderEntry>,
}

impl ProviderRoutingProjection {
    /// An empty registry projection.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Construct a projection with sorted, unique providers and models.
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError::TooManyProviders`] above the derived group
    /// bound, [`PayloadError::TooManyModels`] above the total model bound,
    /// [`PayloadError::DuplicateProvider`] for a repeated identity, or
    /// [`PayloadError::TooLarge`] when the canonical bytes exceed the payload
    /// bound. Group/model-level invariants are enforced by
    /// [`ProviderEntry::new`] and [`ModelEntry::new`].
    pub fn new(mut providers: Vec<ProviderEntry>) -> Result<Self, PayloadError> {
        if providers.len() > CONTROL_PROVIDER_GROUPS_MAX {
            return Err(PayloadError::TooManyProviders {
                actual: providers.len(),
                limit: CONTROL_PROVIDER_GROUPS_MAX,
            });
        }
        providers.sort_unstable_by(|left, right| left.id.cmp(&right.id));
        if providers.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(PayloadError::DuplicateProvider);
        }
        let mut total = 0usize;
        for provider in &providers {
            total =
                total
                    .checked_add(provider.models.len())
                    .ok_or(PayloadError::TooManyModels {
                        actual: usize::MAX,
                        limit: CONTROL_MODELS_MAX,
                    })?;
            if total > CONTROL_MODELS_MAX {
                return Err(PayloadError::TooManyModels {
                    actual: total,
                    limit: CONTROL_MODELS_MAX,
                });
            }
        }
        let projection = Self { providers };
        let bytes = projection.canonical_bytes();
        if bytes.len() > CONTROL_PAYLOAD_MAX_BYTES {
            return Err(PayloadError::TooLarge {
                actual: bytes.len(),
                limit: CONTROL_PAYLOAD_MAX_BYTES,
            });
        }
        Ok(projection)
    }

    /// Sorted provider groups.
    #[must_use]
    pub fn providers(&self) -> &[ProviderEntry] {
        &self.providers
    }

    /// Encode the exact canonical UTF-8 bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(br#"{"domain":"provider-routing","providers":["#);
        for (provider_index, provider) in self.providers.iter().enumerate() {
            if provider_index > 0 {
                out.push(b',');
            }
            out.extend_from_slice(br#"{"id":"#);
            append_json_string(&mut out, &provider.id);
            out.extend_from_slice(br#","models":["#);
            for (model_index, model) in provider.models.iter().enumerate() {
                if model_index > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(br#"{"name":"#);
                append_json_string(&mut out, &model.name);
                out.extend_from_slice(br#","capabilities":["#);
                for (capability_index, capability) in model.capabilities.iter().enumerate() {
                    if capability_index > 0 {
                        out.push(b',');
                    }
                    append_json_string(&mut out, capability.label());
                }
                out.extend_from_slice(b"],\"context_window_tokens\":");
                out.extend_from_slice(model.context_window_tokens.to_string().as_bytes());
                out.extend_from_slice(b",\"input_cost_weight\":");
                out.extend_from_slice(model.input_cost_weight.to_string().as_bytes());
                out.extend_from_slice(b",\"output_cost_weight\":");
                out.extend_from_slice(model.output_cost_weight.to_string().as_bytes());
                out.push(b'}');
            }
            out.extend_from_slice(b"]}");
        }
        out.extend_from_slice(b"]}");
        out
    }

    /// Lowercase SHA-256 digest of [`Self::canonical_bytes`].
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::of(&self.canonical_bytes())
    }

    /// Parse and validate exactly canonical provider-routing bytes.
    ///
    /// The payload is depth-gated at [`CONTROL_JSON_DEPTH_MAX`] before
    /// schema parsing, must carry the exact `provider-routing` domain, must
    /// use the exact field order with no unknown or duplicate field, and must
    /// re-encode byte-for-byte. Unsorted or non-canonical input is refused.
    ///
    /// # Errors
    ///
    /// Returns a [`PayloadError`] describing the first bound or schema
    /// violation.
    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, PayloadError> {
        if bytes.len() > CONTROL_PAYLOAD_MAX_BYTES {
            return Err(PayloadError::TooLarge {
                actual: bytes.len(),
                limit: CONTROL_PAYLOAD_MAX_BYTES,
            });
        }
        match validate_json_depth(bytes, CONTROL_JSON_DEPTH_MAX) {
            Ok(()) => {}
            Err(IpcError::PayloadTooLarge { .. }) => {
                return Err(PayloadError::JsonDepthExceeded {
                    limit: CONTROL_JSON_DEPTH_MAX,
                });
            }
            Err(_) => return Err(PayloadError::InvalidJson),
        }
        let providers = parse_projection(bytes)?;
        let projection = Self::new(providers)?;
        if projection.canonical_bytes() != bytes {
            return Err(PayloadError::NonCanonical);
        }
        Ok(projection)
    }
}

pub(crate) fn check_text(field: &'static str, value: &str) -> Result<(), PayloadError> {
    match text_violation(value) {
        Some(reason) => Err(PayloadError::InvalidText { field, reason }),
        None => Ok(()),
    }
}

pub(crate) fn text_violation(value: &str) -> Option<TextViolation> {
    if value.is_empty() {
        return Some(TextViolation::Empty);
    }
    if value.len() > CONTROL_STRING_MAX_BYTES {
        return Some(TextViolation::TooLong {
            limit: CONTROL_STRING_MAX_BYTES,
            actual: value.len(),
        });
    }
    if value.chars().any(char::is_control) {
        return Some(TextViolation::ControlCharacter);
    }
    None
}

pub(crate) fn append_json_string(out: &mut Vec<u8>, value: &str) {
    out.push(b'"');
    for character in value.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(br#"\\"#),
            '\u{0008}' => out.extend_from_slice(br#"\b"#),
            '\u{000c}' => out.extend_from_slice(br#"\f"#),
            '\n' => out.extend_from_slice(br#"\n"#),
            '\r' => out.extend_from_slice(br#"\r"#),
            '\t' => out.extend_from_slice(br#"\t"#),
            '\u{0000}'..='\u{001f}' => {
                out.extend_from_slice(format!(r#"\u{:04x}"#, character as u32).as_bytes());
            }
            _ => out.extend_from_slice(character.encode_utf8(&mut [0; 4]).as_bytes()),
        }
    }
    out.push(b'"');
}

struct PayloadReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> PayloadReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), PayloadError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(PayloadError::InvalidJson)
        }
    }

    fn expect_key(&mut self, key: &str) -> Result<(), PayloadError> {
        self.expect(b'"')?;
        let expected = key.as_bytes();
        let remaining = self.remaining();
        if expected.len() > remaining {
            return Err(PayloadError::InvalidJson);
        }
        let start = self.pos;
        let end = start + expected.len();
        if &self.bytes[start..end] != expected {
            return Err(PayloadError::InvalidJson);
        }
        self.pos = end;
        self.expect(b'"')?;
        self.expect(b':')
    }

    fn string(&mut self) -> Result<String, PayloadError> {
        let start = self.pos;
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let byte = self.peek().ok_or(PayloadError::InvalidJson)?;
            match byte {
                b'"' => {
                    self.pos += 1;
                    break;
                }
                b'\\' => {
                    self.pos += 1;
                    self.escape(&mut out)?;
                }
                0x00..=0x1f => return Err(PayloadError::InvalidJson),
                _ => {
                    let remaining = &self.bytes[self.pos..];
                    let text =
                        std::str::from_utf8(remaining).map_err(|_| PayloadError::InvalidJson)?;
                    let character = text.chars().next().ok_or(PayloadError::InvalidJson)?;
                    out.push(character);
                    self.pos += character.len_utf8();
                }
            }
        }
        let raw = &self.bytes[start..self.pos];
        let mut canonical = Vec::new();
        append_json_string(&mut canonical, &out);
        if canonical != raw {
            return Err(PayloadError::NonCanonical);
        }
        Ok(out)
    }

    fn escape(&mut self, out: &mut String) -> Result<(), PayloadError> {
        let escaped = self.peek().ok_or(PayloadError::InvalidJson)?;
        self.pos += 1;
        match escaped {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'b' => out.push('\u{0008}'),
            b'f' => out.push('\u{000c}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => {
                let mut code = 0u32;
                for _ in 0..4 {
                    let digit = self.peek().ok_or(PayloadError::InvalidJson)?;
                    self.pos += 1;
                    let value = match digit {
                        b'0'..=b'9' => u32::from(digit - b'0'),
                        b'a'..=b'f' => u32::from(digit - b'a') + 10,
                        b'A'..=b'F' => u32::from(digit - b'A') + 10,
                        _ => return Err(PayloadError::InvalidJson),
                    };
                    code = code * 16 + value;
                }
                let character = char::from_u32(code).ok_or(PayloadError::InvalidJson)?;
                out.push(character);
            }
            _ => return Err(PayloadError::InvalidJson),
        }
        Ok(())
    }

    fn u32_field(&mut self, field: &'static str) -> Result<u32, PayloadError> {
        let first = self.peek().ok_or(PayloadError::InvalidJson)?;
        if !first.is_ascii_digit() {
            return Err(PayloadError::InvalidJson);
        }
        let start = self.pos;
        if first == b'0' {
            self.pos += 1;
            if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err(PayloadError::InvalidJson);
            }
        } else {
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let raw = &self.bytes[start..self.pos];
        let mut value: u32 = 0;
        for &byte in raw {
            value = value
                .checked_mul(10)
                .and_then(|current| current.checked_add(u32::from(byte - b'0')))
                .ok_or(PayloadError::NumberOutOfRange { field })?;
        }
        Ok(value)
    }
}

fn parse_projection(bytes: &[u8]) -> Result<Vec<ProviderEntry>, PayloadError> {
    let mut reader = PayloadReader::new(bytes);
    reader.expect(b'{')?;
    reader.expect_key("domain")?;
    if reader.string()? != PROVIDER_ROUTING_DOMAIN {
        return Err(PayloadError::InvalidDomain);
    }
    reader.expect(b',')?;
    reader.expect_key("providers")?;
    reader.expect(b'[')?;
    let mut providers = Vec::new();
    let mut total_models = 0usize;
    if reader.peek() == Some(b']') {
        reader.pos += 1;
    } else {
        loop {
            if providers.len() >= CONTROL_PROVIDER_GROUPS_MAX {
                return Err(PayloadError::TooManyProviders {
                    actual: providers.len() + 1,
                    limit: CONTROL_PROVIDER_GROUPS_MAX,
                });
            }
            let (provider, next_total) = parse_provider(&mut reader, total_models)?;
            total_models = next_total;
            providers.push(provider);
            match reader.peek() {
                Some(b',') => {
                    reader.pos += 1;
                }
                Some(b']') => {
                    reader.pos += 1;
                    break;
                }
                _ => return Err(PayloadError::InvalidJson),
            }
        }
    }
    reader.expect(b'}')?;
    if reader.remaining() != 0 {
        return Err(PayloadError::InvalidJson);
    }
    Ok(providers)
}

fn parse_provider(
    reader: &mut PayloadReader<'_>,
    mut total_models: usize,
) -> Result<(ProviderEntry, usize), PayloadError> {
    reader.expect(b'{')?;
    reader.expect_key("id")?;
    let id = reader.string()?;
    reader.expect(b',')?;
    reader.expect_key("models")?;
    reader.expect(b'[')?;
    let mut models = Vec::new();
    if reader.peek() == Some(b']') {
        reader.pos += 1;
    } else {
        loop {
            if total_models >= CONTROL_MODELS_MAX {
                return Err(PayloadError::TooManyModels {
                    actual: total_models + 1,
                    limit: CONTROL_MODELS_MAX,
                });
            }
            models.push(parse_model(reader)?);
            total_models += 1;
            match reader.peek() {
                Some(b',') => {
                    reader.pos += 1;
                }
                Some(b']') => {
                    reader.pos += 1;
                    break;
                }
                _ => return Err(PayloadError::InvalidJson),
            }
        }
    }
    reader.expect(b'}')?;
    Ok((ProviderEntry::new(id, models)?, total_models))
}

fn parse_model(reader: &mut PayloadReader<'_>) -> Result<ModelEntry, PayloadError> {
    reader.expect(b'{')?;
    reader.expect_key("name")?;
    let name = reader.string()?;
    reader.expect(b',')?;
    reader.expect_key("capabilities")?;
    reader.expect(b'[')?;
    let mut capabilities = Vec::new();
    if reader.peek() == Some(b']') {
        reader.pos += 1;
    } else {
        loop {
            if capabilities.len() >= CONTROL_CAPABILITIES_MAX {
                return Err(PayloadError::TooManyCapabilities {
                    actual: capabilities.len() + 1,
                    limit: CONTROL_CAPABILITIES_MAX,
                });
            }
            let label = reader.string()?;
            let capability =
                Capability::from_label(&label).ok_or(PayloadError::UnknownCapability)?;
            capabilities.push(capability);
            match reader.peek() {
                Some(b',') => {
                    reader.pos += 1;
                }
                Some(b']') => {
                    reader.pos += 1;
                    break;
                }
                _ => return Err(PayloadError::InvalidJson),
            }
        }
    }
    reader.expect(b',')?;
    reader.expect_key("context_window_tokens")?;
    let context_window_tokens = reader.u32_field("context_window_tokens")?;
    reader.expect(b',')?;
    reader.expect_key("input_cost_weight")?;
    let input_cost_weight = reader.u32_field("input_cost_weight")?;
    reader.expect(b',')?;
    reader.expect_key("output_cost_weight")?;
    let output_cost_weight = reader.u32_field("output_cost_weight")?;
    reader.expect(b'}')?;
    ModelEntry::new(
        name,
        capabilities,
        context_window_tokens,
        input_cost_weight,
        output_cost_weight,
    )
}
