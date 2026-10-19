//! Binary control record header, bodies, and exact encode/decode.

use std::fmt;

use super::error::ControlError;
use super::ids::{AckId, Digest, LifetimeId, PublicationId, ReceiptId, SessionId};
use super::payload::{ProviderRoutingProjection, text_violation};
use super::{
    BOOTSTRAP_FORMAT_VERSION, CONTROL_FRAME_MAX_BYTES, CONTROL_HEADER_BYTES, CONTROL_MAGIC,
    CONTROL_PAYLOAD_MAX_BYTES, CONTROL_PROFILE, CONTROL_PROTOCOL_VERSION,
    CONTROL_SMALL_RECORD_MAX_BYTES, CONTROL_STRING_MAX_BYTES, CONTROL_VERSION, DELEGATION_PURPOSE,
    KEY_MATERIAL_PROFILE, KEY_TYPE_ECDSA_P256, ROLE_CORE, ROLE_HELPER,
};

/// Record kind tag (`u16`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `1` Core to helper establishment echo.
    Establish,
    /// `2` helper to Core establishment confirmation.
    Established,
    /// `3` helper to Core registry projection.
    Projection,
    /// `4` Core to helper publication.
    Publish,
    /// `5` helper to Core publication acknowledgement.
    Ack,
    /// `6` Core to helper binding request.
    Bind,
    /// `7` helper to Core binding receipt.
    Bound,
    /// `8` either direction invalidation.
    Invalidate,
    /// `9` reserved; never legal on the wire.
    Reserved,
    /// `10` helper to Core fresh lifetime announcement.
    Lifetime,
    /// `11` Core to helper strict data-frame admission.
    Admit,
    /// `12` helper to Core admission confirmation.
    Admitted,
    /// `13` either direction terminal error.
    Error,
}

impl Kind {
    /// Decode the wire tag.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::Establish),
            2 => Some(Self::Established),
            3 => Some(Self::Projection),
            4 => Some(Self::Publish),
            5 => Some(Self::Ack),
            6 => Some(Self::Bind),
            7 => Some(Self::Bound),
            8 => Some(Self::Invalidate),
            9 => Some(Self::Reserved),
            10 => Some(Self::Lifetime),
            11 => Some(Self::Admit),
            12 => Some(Self::Admitted),
            13 => Some(Self::Error),
            _ => None,
        }
    }

    /// Wire tag.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Establish => 1,
            Self::Established => 2,
            Self::Projection => 3,
            Self::Publish => 4,
            Self::Ack => 5,
            Self::Bind => 6,
            Self::Bound => 7,
            Self::Invalidate => 8,
            Self::Reserved => 9,
            Self::Lifetime => 10,
            Self::Admit => 11,
            Self::Admitted => 12,
            Self::Error => 13,
        }
    }

    /// Legal direction for this kind.
    #[must_use]
    pub const fn direction(self) -> Direction {
        match self {
            Self::Establish | Self::Publish | Self::Bind | Self::Admit => Direction::CoreToHelper,
            Self::Established
            | Self::Projection
            | Self::Ack
            | Self::Bound
            | Self::Lifetime
            | Self::Admitted => Direction::HelperToCore,
            Self::Invalidate | Self::Error => Direction::Either,
            Self::Reserved => Direction::Neither,
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Establish => "Establish",
            Self::Established => "Established",
            Self::Projection => "Projection",
            Self::Publish => "Publish",
            Self::Ack => "Ack",
            Self::Bind => "Bind",
            Self::Bound => "Bound",
            Self::Invalidate => "Invalidate",
            Self::Reserved => "Reserved",
            Self::Lifetime => "Lifetime",
            Self::Admit => "Admit",
            Self::Admitted => "Admitted",
            Self::Error => "Error",
        };
        f.write_str(label)
    }
}

/// Fixed sender byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sender {
    /// `1` Core supervisor.
    Core,
    /// `2` AI helper.
    Helper,
}

impl Sender {
    /// Decode the sender byte.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Core),
            2 => Some(Self::Helper),
            _ => None,
        }
    }

    /// Wire byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Core => 1,
            Self::Helper => 2,
        }
    }
}

impl fmt::Display for Sender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core => f.write_str("core"),
            Self::Helper => f.write_str("helper"),
        }
    }
}

/// Legal record direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Core to helper only.
    CoreToHelper,
    /// Helper to Core only.
    HelperToCore,
    /// Both directions.
    Either,
    /// No direction (reserved).
    Neither,
}

impl Direction {
    /// Whether `sender` is legal for this direction.
    #[must_use]
    pub const fn allows(self, sender: Sender) -> bool {
        match self {
            Self::CoreToHelper => matches!(sender, Sender::Core),
            Self::HelperToCore => matches!(sender, Sender::Helper),
            Self::Either => true,
            Self::Neither => false,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CoreToHelper => f.write_str("Core to helper"),
            Self::HelperToCore => f.write_str("helper to Core"),
            Self::Either => f.write_str("either direction"),
            Self::Neither => f.write_str("no direction"),
        }
    }
}

/// Domain enum; domain byte `1` is exactly `provider-routing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Domain {
    /// Provider-routing publication domain.
    ProviderRouting,
}

impl Domain {
    /// Decode the domain byte.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ProviderRouting),
            _ => None,
        }
    }

    /// Wire byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::ProviderRouting => 1,
        }
    }
}

/// Why a lifetime or publication was invalidated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// Source mutation.
    SourceMutation,
    /// Registry mutation.
    RegistryMutation,
    /// Reset.
    Reset,
    /// Supersession.
    Supersession,
    /// Grant loss.
    GrantLoss,
    /// Shutdown.
    Shutdown,
}

impl Reason {
    /// Decode the reason byte.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::SourceMutation),
            2 => Some(Self::RegistryMutation),
            3 => Some(Self::Reset),
            4 => Some(Self::Supersession),
            5 => Some(Self::GrantLoss),
            6 => Some(Self::Shutdown),
            _ => None,
        }
    }

    /// Wire byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::SourceMutation => 1,
            Self::RegistryMutation => 2,
            Self::Reset => 3,
            Self::Supersession => 4,
            Self::GrantLoss => 5,
            Self::Shutdown => 6,
        }
    }
}

/// Closed terminal error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Invalid control.
    InvalidControl,
    /// Unavailable.
    Unavailable,
    /// Resource limit.
    ResourceLimit,
    /// Timeout.
    Timeout,
}

impl ErrorCode {
    /// Decode the error byte.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::InvalidControl),
            2 => Some(Self::Unavailable),
            3 => Some(Self::ResourceLimit),
            4 => Some(Self::Timeout),
            _ => None,
        }
    }

    /// Wire byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::InvalidControl => 1,
            Self::Unavailable => 2,
            Self::ResourceLimit => 3,
            Self::Timeout => 4,
        }
    }

    /// Fixed local diagnostic text; never includes caller bytes.
    #[must_use]
    pub const fn diagnostic(self) -> &'static str {
        match self {
            Self::InvalidControl => "invalid control record",
            Self::Unavailable => "provider publication unavailable",
            Self::ResourceLimit => "provider publication resource limit",
            Self::Timeout => "provider publication timeout",
        }
    }
}

/// Exact publication tuple: domain, identity, version, and payload digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuple {
    /// Domain tag.
    pub domain: Domain,
    /// 40-byte publication identity.
    pub publication_id: PublicationId,
    /// Core snapshot version, starting at `1`.
    pub snapshot_version: u64,
    /// Canonical payload digest.
    pub digest: Digest,
}

impl Tuple {
    /// Build a provider-routing tuple.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::ZeroValue`] for a zero snapshot version or a
    /// zero publication-version suffix.
    pub fn new(
        publication_id: PublicationId,
        snapshot_version: u64,
        digest: Digest,
    ) -> Result<Self, ControlError> {
        let tuple = Self {
            domain: Domain::ProviderRouting,
            publication_id,
            snapshot_version,
            digest,
        };
        tuple.validate()?;
        Ok(tuple)
    }

    fn validate(&self) -> Result<(), ControlError> {
        if self.snapshot_version == 0 {
            return Err(ControlError::ZeroValue {
                field: "snapshot_version",
            });
        }
        if self.publication_id.version() == 0 {
            return Err(ControlError::ZeroValue {
                field: "publication_version",
            });
        }
        Ok(())
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ControlError> {
        self.validate()?;
        out.push(self.domain.code());
        out.extend_from_slice(self.publication_id.as_bytes());
        out.extend_from_slice(&self.snapshot_version.to_be_bytes());
        out.extend_from_slice(self.digest.as_bytes());
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ControlError> {
        let domain_code = reader.u8("tuple.domain")?;
        let domain = Domain::from_code(domain_code).ok_or(ControlError::UnknownDomain {
            actual: domain_code,
        })?;
        let publication_id = PublicationId::new(reader.array("tuple.publication_id")?);
        let snapshot_version = reader.u64("tuple.snapshot_version")?;
        let digest = Digest::new(reader.array("tuple.digest")?);
        let tuple = Self {
            domain,
            publication_id,
            snapshot_version,
            digest,
        };
        tuple.validate()?;
        Ok(tuple)
    }
}

// ── body structs ────────────────────────────────────────────────────────────

/// Non-secret establishment echo carried by `Establish` and `Established`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishmentEcho {
    /// Bootstrap manifest format version (`1`).
    pub bootstrap_format_version: u16,
    /// Control protocol version (`1`).
    pub control_protocol_version: u16,
    /// Core instance nonce.
    pub core_instance_nonce: super::Nonce,
    /// Launch nonce; must equal the header session.
    pub launch_nonce: SessionId,
    /// Component name.
    pub component_name: String,
    /// Exact component descriptor version.
    pub descriptor_version: String,
    /// Executable name.
    pub executable_name: String,
    /// Verified executable SHA-256.
    pub executable_sha256: Digest,
    /// Selected component protocol version.
    pub component_protocol_version: u16,
    /// Control-channel nonce.
    pub control_channel_nonce: super::Nonce,
    /// Data-channel nonce.
    pub data_channel_nonce: super::Nonce,
    /// Delegation purpose (`provider-routing-publication`).
    pub delegation_purpose: String,
    /// Control profile (`provider-publication-control/1`).
    pub control_profile: String,
    /// Key-material profile (`1`).
    pub key_material_profile: u8,
    /// Key type (`1`, ECDSA P-256).
    pub key_type: u8,
    /// Core leaf certificate digest.
    pub core_leaf_digest: Digest,
    /// Helper leaf certificate digest.
    pub helper_leaf_digest: Digest,
}

impl EstablishmentEcho {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ControlError> {
        if self.bootstrap_format_version != BOOTSTRAP_FORMAT_VERSION {
            return Err(ControlError::UnsupportedBootstrapVersion {
                actual: self.bootstrap_format_version,
            });
        }
        if self.control_protocol_version != CONTROL_PROTOCOL_VERSION {
            return Err(ControlError::UnsupportedControlProtocolVersion {
                actual: self.control_protocol_version,
            });
        }
        if self.delegation_purpose != DELEGATION_PURPOSE {
            return Err(ControlError::UnexpectedConstant {
                field: "delegation_purpose",
            });
        }
        if self.control_profile != CONTROL_PROFILE {
            return Err(ControlError::UnexpectedConstant {
                field: "control_profile",
            });
        }
        if self.key_material_profile != KEY_MATERIAL_PROFILE {
            return Err(ControlError::UnsupportedKeyMaterialProfile {
                actual: self.key_material_profile,
            });
        }
        if self.key_type != KEY_TYPE_ECDSA_P256 {
            return Err(ControlError::UnsupportedKeyType {
                actual: self.key_type,
            });
        }
        out.extend_from_slice(&self.bootstrap_format_version.to_be_bytes());
        out.extend_from_slice(&self.control_protocol_version.to_be_bytes());
        out.push(ROLE_CORE);
        out.push(ROLE_HELPER);
        out.extend_from_slice(self.core_instance_nonce.as_bytes());
        out.extend_from_slice(self.launch_nonce.as_bytes());
        write_string(out, "component_name", &self.component_name)?;
        write_string(out, "descriptor_version", &self.descriptor_version)?;
        write_string(out, "executable_name", &self.executable_name)?;
        out.extend_from_slice(self.executable_sha256.as_bytes());
        out.extend_from_slice(&self.component_protocol_version.to_be_bytes());
        out.extend_from_slice(self.control_channel_nonce.as_bytes());
        out.extend_from_slice(self.data_channel_nonce.as_bytes());
        write_string(out, "delegation_purpose", &self.delegation_purpose)?;
        write_string(out, "control_profile", &self.control_profile)?;
        out.push(self.key_material_profile);
        out.push(self.key_type);
        out.extend_from_slice(self.core_leaf_digest.as_bytes());
        out.extend_from_slice(self.helper_leaf_digest.as_bytes());
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ControlError> {
        let bootstrap_format_version = reader.u16("bootstrap_format_version")?;
        if bootstrap_format_version != BOOTSTRAP_FORMAT_VERSION {
            return Err(ControlError::UnsupportedBootstrapVersion {
                actual: bootstrap_format_version,
            });
        }
        let control_protocol_version = reader.u16("control_protocol_version")?;
        if control_protocol_version != CONTROL_PROTOCOL_VERSION {
            return Err(ControlError::UnsupportedControlProtocolVersion {
                actual: control_protocol_version,
            });
        }
        let core_role = reader.u8("roles.core")?;
        if core_role != ROLE_CORE {
            return Err(ControlError::InvalidRole {
                index: 0,
                actual: core_role,
            });
        }
        let helper_role = reader.u8("roles.helper")?;
        if helper_role != ROLE_HELPER {
            return Err(ControlError::InvalidRole {
                index: 1,
                actual: helper_role,
            });
        }
        let core_instance_nonce = super::Nonce::new(reader.array("core_instance_nonce")?);
        let launch_nonce = SessionId::new(reader.array("launch_nonce")?);
        let component_name = reader.string("component_name")?.to_owned();
        let descriptor_version = reader.string("descriptor_version")?.to_owned();
        let executable_name = reader.string("executable_name")?.to_owned();
        let executable_sha256 = Digest::new(reader.array("executable_sha256")?);
        let component_protocol_version = reader.u16("component_protocol_version")?;
        let control_channel_nonce = super::Nonce::new(reader.array("control_channel_nonce")?);
        let data_channel_nonce = super::Nonce::new(reader.array("data_channel_nonce")?);
        let delegation_purpose = reader.string("delegation_purpose")?.to_owned();
        if delegation_purpose != DELEGATION_PURPOSE {
            return Err(ControlError::UnexpectedConstant {
                field: "delegation_purpose",
            });
        }
        let control_profile = reader.string("control_profile")?.to_owned();
        if control_profile != CONTROL_PROFILE {
            return Err(ControlError::UnexpectedConstant {
                field: "control_profile",
            });
        }
        let key_material_profile = reader.u8("key_material_profile")?;
        if key_material_profile != KEY_MATERIAL_PROFILE {
            return Err(ControlError::UnsupportedKeyMaterialProfile {
                actual: key_material_profile,
            });
        }
        let key_type = reader.u8("key_type")?;
        if key_type != KEY_TYPE_ECDSA_P256 {
            return Err(ControlError::UnsupportedKeyType { actual: key_type });
        }
        let core_leaf_digest = Digest::new(reader.array("core_leaf_digest")?);
        let helper_leaf_digest = Digest::new(reader.array("helper_leaf_digest")?);
        Ok(Self {
            bootstrap_format_version,
            control_protocol_version,
            core_instance_nonce,
            launch_nonce,
            component_name,
            descriptor_version,
            executable_name,
            executable_sha256,
            component_protocol_version,
            control_channel_nonce,
            data_channel_nonce,
            delegation_purpose,
            control_profile,
            key_material_profile,
            key_type,
            core_leaf_digest,
            helper_leaf_digest,
        })
    }
}

/// `Established` body: the same echo plus a fresh public lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishedBody {
    /// Non-secret establishment echo.
    pub echo: EstablishmentEcho,
    /// Fresh helper lifetime identifier.
    pub lifetime_id: LifetimeId,
}

/// `Projection` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionBody {
    /// Current helper lifetime.
    pub lifetime_id: LifetimeId,
    /// Registry feed revision, starting at `1`.
    pub feed_revision: u64,
    /// Canonical provider-routing projection.
    pub payload: ProviderRoutingProjection,
}

/// `Publish` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishBody {
    /// Current helper lifetime.
    pub lifetime_id: LifetimeId,
    /// Registry feed revision, starting at `1`.
    pub feed_revision: u64,
    /// Exact publication tuple.
    pub tuple: Tuple,
    /// Canonical provider-routing projection.
    pub payload: ProviderRoutingProjection,
}

/// `Ack` body, also used by `Bind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckBody {
    /// Current helper lifetime.
    pub lifetime_id: LifetimeId,
    /// Registry feed revision.
    pub feed_revision: u64,
    /// Exact publication tuple.
    pub tuple: Tuple,
    /// Fresh acknowledgement identifier.
    pub ack_id: AckId,
}

/// `Bind` body is byte-identical to [`AckBody`].
pub type BindBody = AckBody;

/// `Bound` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundBody {
    /// Current helper lifetime.
    pub lifetime_id: LifetimeId,
    /// Registry feed revision.
    pub feed_revision: u64,
    /// Exact publication tuple.
    pub tuple: Tuple,
    /// Fresh helper proof receipt.
    pub receipt: ReceiptId,
}

/// `Invalidate` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidateBody {
    /// Predecessor lifetime.
    pub lifetime_id: LifetimeId,
    /// Predecessor feed revision.
    pub feed_revision: u64,
    /// Closed invalidation reason.
    pub reason: Reason,
}

/// `Lifetime` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifetimeBody {
    /// Fresh lifetime identifier.
    pub lifetime_id: LifetimeId,
    /// Feed revision, starting at `1`.
    pub feed_revision: u64,
}

/// `Admit` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmitBody {
    /// Current helper lifetime.
    pub lifetime_id: LifetimeId,
    /// Registry feed revision.
    pub feed_revision: u64,
    /// Exact publication tuple.
    pub tuple: Tuple,
    /// Current helper proof receipt.
    pub receipt: ReceiptId,
    /// Existing numeric data RPC request ID.
    pub request_id: u64,
    /// SHA-256 of the exact forthcoming data-frame payload bytes.
    pub data_frame_digest: Digest,
}

/// `Admitted` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedBody {
    /// Existing numeric data RPC request ID.
    pub request_id: u64,
    /// Exact data-frame payload digest.
    pub data_frame_digest: Digest,
    /// Current helper lifetime.
    pub lifetime_id: LifetimeId,
}

/// Record body, one variant per kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordBody {
    /// Kind `1`.
    Establish(EstablishmentEcho),
    /// Kind `2`.
    Established(EstablishedBody),
    /// Kind `3`.
    Projection(ProjectionBody),
    /// Kind `4`.
    Publish(PublishBody),
    /// Kind `5`.
    Ack(AckBody),
    /// Kind `6`.
    Bind(AckBody),
    /// Kind `7`.
    Bound(BoundBody),
    /// Kind `8`.
    Invalidate(InvalidateBody),
    /// Kind `9`; never encodable or decodable.
    Reserved,
    /// Kind `10`.
    Lifetime(LifetimeBody),
    /// Kind `11`.
    Admit(AdmitBody),
    /// Kind `12`.
    Admitted(AdmittedBody),
    /// Kind `13`.
    Error(ErrorCode),
}

impl RecordBody {
    /// Wire kind for this body.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        match self {
            Self::Establish(_) => Kind::Establish,
            Self::Established(_) => Kind::Established,
            Self::Projection(_) => Kind::Projection,
            Self::Publish(_) => Kind::Publish,
            Self::Ack(_) => Kind::Ack,
            Self::Bind(_) => Kind::Bind,
            Self::Bound(_) => Kind::Bound,
            Self::Invalidate(_) => Kind::Invalidate,
            Self::Reserved => Kind::Reserved,
            Self::Lifetime(_) => Kind::Lifetime,
            Self::Admit(_) => Kind::Admit,
            Self::Admitted(_) => Kind::Admitted,
            Self::Error(_) => Kind::Error,
        }
    }

    fn launch_nonce(&self) -> Option<SessionId> {
        match self {
            Self::Establish(echo) => Some(echo.launch_nonce),
            Self::Established(body) => Some(body.echo.launch_nonce),
            _ => None,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ControlError> {
        match self {
            Self::Establish(echo) => echo.encode(out),
            Self::Established(body) => {
                body.echo.encode(out)?;
                out.extend_from_slice(body.lifetime_id.as_bytes());
                Ok(())
            }
            Self::Projection(body) => {
                if body.feed_revision == 0 {
                    return Err(ControlError::ZeroValue {
                        field: "feed_revision",
                    });
                }
                let bytes = body.payload.canonical_bytes();
                ensure_payload_size(bytes.len())?;
                out.extend_from_slice(body.lifetime_id.as_bytes());
                out.extend_from_slice(&body.feed_revision.to_be_bytes());
                out.extend_from_slice(Digest::of(&bytes).as_bytes());
                write_payload(out, &bytes)
            }
            Self::Publish(body) => {
                if body.feed_revision == 0 {
                    return Err(ControlError::ZeroValue {
                        field: "feed_revision",
                    });
                }
                let bytes = body.payload.canonical_bytes();
                ensure_payload_size(bytes.len())?;
                if body.tuple.digest != Digest::of(&bytes) {
                    return Err(ControlError::DigestMismatch);
                }
                out.extend_from_slice(body.lifetime_id.as_bytes());
                out.extend_from_slice(&body.feed_revision.to_be_bytes());
                body.tuple.encode(out)?;
                write_payload(out, &bytes)
            }
            Self::Ack(body) | Self::Bind(body) => encode_ack(body, out),
            Self::Bound(body) => {
                if body.feed_revision == 0 {
                    return Err(ControlError::ZeroValue {
                        field: "feed_revision",
                    });
                }
                out.extend_from_slice(body.lifetime_id.as_bytes());
                out.extend_from_slice(&body.feed_revision.to_be_bytes());
                body.tuple.encode(out)?;
                out.extend_from_slice(body.receipt.as_bytes());
                Ok(())
            }
            Self::Invalidate(body) => {
                if body.feed_revision == 0 {
                    return Err(ControlError::ZeroValue {
                        field: "feed_revision",
                    });
                }
                out.extend_from_slice(body.lifetime_id.as_bytes());
                out.extend_from_slice(&body.feed_revision.to_be_bytes());
                out.push(body.reason.code());
                Ok(())
            }
            Self::Reserved => Err(ControlError::ReservedKind),
            Self::Lifetime(body) => {
                if body.feed_revision == 0 {
                    return Err(ControlError::ZeroValue {
                        field: "feed_revision",
                    });
                }
                out.extend_from_slice(body.lifetime_id.as_bytes());
                out.extend_from_slice(&body.feed_revision.to_be_bytes());
                Ok(())
            }
            Self::Admit(body) => {
                if body.feed_revision == 0 {
                    return Err(ControlError::ZeroValue {
                        field: "feed_revision",
                    });
                }
                out.extend_from_slice(body.lifetime_id.as_bytes());
                out.extend_from_slice(&body.feed_revision.to_be_bytes());
                body.tuple.encode(out)?;
                out.extend_from_slice(body.receipt.as_bytes());
                out.extend_from_slice(&body.request_id.to_be_bytes());
                out.extend_from_slice(body.data_frame_digest.as_bytes());
                Ok(())
            }
            Self::Admitted(body) => {
                out.extend_from_slice(&body.request_id.to_be_bytes());
                out.extend_from_slice(body.data_frame_digest.as_bytes());
                out.extend_from_slice(body.lifetime_id.as_bytes());
                Ok(())
            }
            Self::Error(code) => {
                out.push(code.code());
                Ok(())
            }
        }
    }

    fn decode(kind: Kind, reader: &mut Reader<'_>) -> Result<Self, ControlError> {
        match kind {
            Kind::Establish => Ok(Self::Establish(EstablishmentEcho::decode(reader)?)),
            Kind::Established => Ok(Self::Established(EstablishedBody {
                echo: EstablishmentEcho::decode(reader)?,
                lifetime_id: LifetimeId::new(reader.array("lifetime_id")?),
            })),
            Kind::Projection => {
                let lifetime_id = LifetimeId::new(reader.array("lifetime_id")?);
                let feed_revision = reader.u64("feed_revision")?;
                if feed_revision == 0 {
                    return Err(ControlError::ZeroValue {
                        field: "feed_revision",
                    });
                }
                let digest = Digest::new(reader.array("digest")?);
                let bytes = reader.payload()?;
                if digest != Digest::of(bytes) {
                    return Err(ControlError::DigestMismatch);
                }
                let payload = ProviderRoutingProjection::parse_canonical(bytes)
                    .map_err(ControlError::Payload)?;
                Ok(Self::Projection(ProjectionBody {
                    lifetime_id,
                    feed_revision,
                    payload,
                }))
            }
            Kind::Publish => {
                let lifetime_id = LifetimeId::new(reader.array("lifetime_id")?);
                let feed_revision = reader.u64("feed_revision")?;
                if feed_revision == 0 {
                    return Err(ControlError::ZeroValue {
                        field: "feed_revision",
                    });
                }
                let tuple = Tuple::decode(reader)?;
                let bytes = reader.payload()?;
                if tuple.digest != Digest::of(bytes) {
                    return Err(ControlError::DigestMismatch);
                }
                let payload = ProviderRoutingProjection::parse_canonical(bytes)
                    .map_err(ControlError::Payload)?;
                Ok(Self::Publish(PublishBody {
                    lifetime_id,
                    feed_revision,
                    tuple,
                    payload,
                }))
            }
            Kind::Ack => Ok(Self::Ack(decode_ack(reader)?)),
            Kind::Bind => Ok(Self::Bind(decode_ack(reader)?)),
            Kind::Bound => {
                let lifetime_id = LifetimeId::new(reader.array("lifetime_id")?);
                let feed_revision = reader.u64("feed_revision")?;
                if feed_revision == 0 {
                    return Err(ControlError::ZeroValue {
                        field: "feed_revision",
                    });
                }
                let tuple = Tuple::decode(reader)?;
                let receipt = ReceiptId::new(reader.array("receipt")?);
                Ok(Self::Bound(BoundBody {
                    lifetime_id,
                    feed_revision,
                    tuple,
                    receipt,
                }))
            }
            Kind::Invalidate => {
                let lifetime_id = LifetimeId::new(reader.array("lifetime_id")?);
                let feed_revision = reader.u64("feed_revision")?;
                if feed_revision == 0 {
                    return Err(ControlError::ZeroValue {
                        field: "feed_revision",
                    });
                }
                let code = reader.u8("reason")?;
                let reason =
                    Reason::from_code(code).ok_or(ControlError::UnknownReason { actual: code })?;
                Ok(Self::Invalidate(InvalidateBody {
                    lifetime_id,
                    feed_revision,
                    reason,
                }))
            }
            Kind::Reserved => Err(ControlError::ReservedKind),
            Kind::Lifetime => {
                let lifetime_id = LifetimeId::new(reader.array("lifetime_id")?);
                let feed_revision = reader.u64("feed_revision")?;
                if feed_revision == 0 {
                    return Err(ControlError::ZeroValue {
                        field: "feed_revision",
                    });
                }
                Ok(Self::Lifetime(LifetimeBody {
                    lifetime_id,
                    feed_revision,
                }))
            }
            Kind::Admit => {
                let lifetime_id = LifetimeId::new(reader.array("lifetime_id")?);
                let feed_revision = reader.u64("feed_revision")?;
                if feed_revision == 0 {
                    return Err(ControlError::ZeroValue {
                        field: "feed_revision",
                    });
                }
                let tuple = Tuple::decode(reader)?;
                let receipt = ReceiptId::new(reader.array("receipt")?);
                let request_id = reader.u64("request_id")?;
                let data_frame_digest = Digest::new(reader.array("data_frame_digest")?);
                Ok(Self::Admit(AdmitBody {
                    lifetime_id,
                    feed_revision,
                    tuple,
                    receipt,
                    request_id,
                    data_frame_digest,
                }))
            }
            Kind::Admitted => {
                let request_id = reader.u64("request_id")?;
                let data_frame_digest = Digest::new(reader.array("data_frame_digest")?);
                let lifetime_id = LifetimeId::new(reader.array("lifetime_id")?);
                Ok(Self::Admitted(AdmittedBody {
                    request_id,
                    data_frame_digest,
                    lifetime_id,
                }))
            }
            Kind::Error => {
                let code = reader.u8("error.code")?;
                let code = ErrorCode::from_code(code)
                    .ok_or(ControlError::UnknownErrorCode { actual: code })?;
                Ok(Self::Error(code))
            }
        }
    }
}

fn encode_ack(body: &AckBody, out: &mut Vec<u8>) -> Result<(), ControlError> {
    if body.feed_revision == 0 {
        return Err(ControlError::ZeroValue {
            field: "feed_revision",
        });
    }
    out.extend_from_slice(body.lifetime_id.as_bytes());
    out.extend_from_slice(&body.feed_revision.to_be_bytes());
    body.tuple.encode(out)?;
    out.extend_from_slice(body.ack_id.as_bytes());
    Ok(())
}

fn decode_ack(reader: &mut Reader<'_>) -> Result<AckBody, ControlError> {
    let lifetime_id = LifetimeId::new(reader.array("lifetime_id")?);
    let feed_revision = reader.u64("feed_revision")?;
    if feed_revision == 0 {
        return Err(ControlError::ZeroValue {
            field: "feed_revision",
        });
    }
    let tuple = Tuple::decode(reader)?;
    let ack_id = AckId::new(reader.array("ack_id")?);
    Ok(AckBody {
        lifetime_id,
        feed_revision,
        tuple,
        ack_id,
    })
}

/// One complete control record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlRecord {
    /// Authenticated sender role.
    pub sender: Sender,
    /// Per-direction sequence.
    pub sequence: u64,
    /// Launch-nonce session binding.
    pub session_id: SessionId,
    /// Typed record body.
    pub body: RecordBody,
}

impl ControlRecord {
    /// The fixed header view of this record.
    #[must_use]
    pub fn header(&self) -> RecordHeader {
        RecordHeader {
            kind: self.body.kind(),
            sender: self.sender,
            sequence: self.sequence,
            session_id: self.session_id,
        }
    }

    /// Encode exactly one complete control record.
    ///
    /// # Errors
    ///
    /// Returns a [`ControlError`] for the reserved kind, a wrong sender for
    /// the kind, sequence `0`, invalid or inconsistent fields, an oversize
    /// payload/record, or a record exceeding the small-record bound.
    pub fn encode(&self) -> Result<Vec<u8>, ControlError> {
        let kind = self.body.kind();
        if kind == Kind::Reserved {
            return Err(ControlError::ReservedKind);
        }
        if let Some(nonce) = self.body.launch_nonce() {
            if nonce != self.session_id {
                return Err(ControlError::SessionMismatch);
            }
        }
        let header = self.header().encode()?;
        let mut body = Vec::new();
        self.body.encode(&mut body)?;
        let total = CONTROL_HEADER_BYTES
            .checked_add(body.len())
            .ok_or(ControlError::LengthOverflow)?;
        if total > CONTROL_FRAME_MAX_BYTES {
            return Err(ControlError::FrameTooLarge {
                actual: total,
                limit: CONTROL_FRAME_MAX_BYTES,
            });
        }
        if !matches!(
            &self.body,
            RecordBody::Projection(_) | RecordBody::Publish(_)
        ) && total > CONTROL_SMALL_RECORD_MAX_BYTES
        {
            return Err(ControlError::SmallRecordTooLarge {
                actual: total,
                limit: CONTROL_SMALL_RECORD_MAX_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&header);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode exactly one complete control record.
    ///
    /// # Errors
    ///
    /// Returns a [`ControlError`] for truncation, trailing bytes, unknown or
    /// reserved kinds, unknown version/sender/domain/reason/error values,
    /// wrong direction or role bytes, sequence `0`, zero versions, invalid
    /// canonical payload bytes, a digest mismatch, an establishment session
    /// mismatch, or an exceeded bound.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
        if bytes.len() > CONTROL_FRAME_MAX_BYTES {
            return Err(ControlError::FrameTooLarge {
                actual: bytes.len(),
                limit: CONTROL_FRAME_MAX_BYTES,
            });
        }
        let (header, consumed) = RecordHeader::decode(bytes)?;
        let mut reader = Reader::new(&bytes[consumed..]);
        let body = RecordBody::decode(header.kind, &mut reader)?;
        if reader.remaining() != 0 {
            return Err(ControlError::TrailingBytes {
                remaining: reader.remaining(),
            });
        }
        if let Some(nonce) = body.launch_nonce() {
            if nonce != header.session_id {
                return Err(ControlError::SessionMismatch);
            }
        }
        if !matches!(&body, RecordBody::Projection(_) | RecordBody::Publish(_)) {
            ensure_small_record(bytes.len())?;
        }
        Ok(Self {
            sender: header.sender,
            sequence: header.sequence,
            session_id: header.session_id,
            body,
        })
    }
}

/// Fixed control record header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    /// Record kind.
    pub kind: Kind,
    /// Sender role.
    pub sender: Sender,
    /// Per-direction sequence.
    pub sequence: u64,
    /// Launch-nonce session binding.
    pub session_id: SessionId,
}

impl RecordHeader {
    /// Encode the fixed 49-byte header.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::ReservedKind`] for the reserved kind,
    /// [`ControlError::SequenceZero`] for sequence `0`, or
    /// [`ControlError::WrongDirection`] for an illegal sender.
    pub fn encode(&self) -> Result<[u8; CONTROL_HEADER_BYTES], ControlError> {
        if self.kind == Kind::Reserved {
            return Err(ControlError::ReservedKind);
        }
        if self.sequence == 0 {
            return Err(ControlError::SequenceZero);
        }
        if !self.kind.direction().allows(self.sender) {
            return Err(ControlError::WrongDirection {
                kind: self.kind,
                sender: self.sender,
            });
        }
        let mut out = [0u8; CONTROL_HEADER_BYTES];
        out[0..4].copy_from_slice(&CONTROL_MAGIC);
        out[4..6].copy_from_slice(&CONTROL_VERSION.to_be_bytes());
        out[6..8].copy_from_slice(&self.kind.code().to_be_bytes());
        out[8] = self.sender.code();
        out[9..17].copy_from_slice(&self.sequence.to_be_bytes());
        out[17..49].copy_from_slice(self.session_id.as_bytes());
        Ok(out)
    }

    /// Decode one header from the start of `bytes` and report bytes consumed.
    ///
    /// Trailing body bytes are left to the caller.
    ///
    /// # Errors
    ///
    /// Returns a [`ControlError`] for truncation, bad magic/version/kind/
    /// sender, the reserved kind, sequence `0`, or an illegal direction.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), ControlError> {
        let mut reader = Reader::new(bytes);
        let magic = reader.take(4, "magic")?;
        if magic != CONTROL_MAGIC {
            return Err(ControlError::InvalidMagic);
        }
        let version = reader.u16("version")?;
        if version != CONTROL_VERSION {
            return Err(ControlError::UnsupportedVersion { actual: version });
        }
        let kind_code = reader.u16("kind")?;
        let kind =
            Kind::from_code(kind_code).ok_or(ControlError::UnknownKind { actual: kind_code })?;
        if kind == Kind::Reserved {
            return Err(ControlError::ReservedKind);
        }
        let sender_code = reader.u8("sender")?;
        let sender = Sender::from_code(sender_code).ok_or(ControlError::UnknownSender {
            actual: sender_code,
        })?;
        if !kind.direction().allows(sender) {
            return Err(ControlError::WrongDirection { kind, sender });
        }
        let sequence = reader.u64("sequence")?;
        if sequence == 0 {
            return Err(ControlError::SequenceZero);
        }
        let session_id = SessionId::new(reader.array("session_id")?);
        Ok((
            Self {
                kind,
                sender,
                sequence,
                session_id,
            },
            CONTROL_HEADER_BYTES,
        ))
    }
}

pub(crate) fn ensure_small_record(total: usize) -> Result<(), ControlError> {
    if total > CONTROL_SMALL_RECORD_MAX_BYTES {
        return Err(ControlError::SmallRecordTooLarge {
            actual: total,
            limit: CONTROL_SMALL_RECORD_MAX_BYTES,
        });
    }
    Ok(())
}

// ── byte reader/writer helpers ───────────────────────────────────────────────

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, count: usize, field: &'static str) -> Result<&'a [u8], ControlError> {
        let remaining = self.remaining();
        if count > remaining {
            return Err(ControlError::Truncated {
                field,
                needed: count,
                remaining,
            });
        }
        let start = self.pos;
        self.pos += count;
        Ok(&self.bytes[start..self.pos])
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, ControlError> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, ControlError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, ControlError> {
        let bytes = self.take(4, field)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, ControlError> {
        let bytes = self.take(8, field)?;
        let mut value = [0u8; 8];
        value.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(value))
    }

    fn array<const LEN: usize>(&mut self, field: &'static str) -> Result<[u8; LEN], ControlError> {
        let bytes = self.take(LEN, field)?;
        let mut value = [0u8; LEN];
        value.copy_from_slice(bytes);
        Ok(value)
    }

    fn string(&mut self, field: &'static str) -> Result<&'a str, ControlError> {
        let length = self.u32(field)? as usize;
        if length > CONTROL_STRING_MAX_BYTES {
            return Err(ControlError::FieldTooLarge {
                field,
                limit: CONTROL_STRING_MAX_BYTES,
                actual: length,
            });
        }
        let bytes = self.take(length, field)?;
        let text = std::str::from_utf8(bytes).map_err(|_| ControlError::InvalidText {
            field,
            reason: super::TextViolation::InvalidUtf8,
        })?;
        if let Some(reason) = text_violation(text) {
            return Err(ControlError::InvalidText { field, reason });
        }
        Ok(text)
    }

    fn payload(&mut self) -> Result<&'a [u8], ControlError> {
        let length = self.u32("payload.length")? as usize;
        if length > CONTROL_PAYLOAD_MAX_BYTES {
            return Err(ControlError::PayloadTooLarge {
                actual: length,
                limit: CONTROL_PAYLOAD_MAX_BYTES,
            });
        }
        self.take(length, "payload")
    }
}

fn write_string(out: &mut Vec<u8>, field: &'static str, value: &str) -> Result<(), ControlError> {
    if let Some(reason) = text_violation(value) {
        return Err(ControlError::InvalidText { field, reason });
    }
    let length = u32::try_from(value.len()).map_err(|_| ControlError::LengthOverflow)?;
    let total = checked_extend_len(out.len(), 4 + value.len())?;
    if total > CONTROL_FRAME_MAX_BYTES {
        return Err(ControlError::FrameTooLarge {
            actual: total,
            limit: CONTROL_FRAME_MAX_BYTES,
        });
    }
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn ensure_payload_size(length: usize) -> Result<(), ControlError> {
    if length > CONTROL_PAYLOAD_MAX_BYTES {
        return Err(ControlError::PayloadTooLarge {
            actual: length,
            limit: CONTROL_PAYLOAD_MAX_BYTES,
        });
    }
    Ok(())
}

fn write_payload(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ControlError> {
    ensure_payload_size(bytes.len())?;
    let length = u32::try_from(bytes.len()).map_err(|_| ControlError::LengthOverflow)?;
    let total = checked_extend_len(out.len(), 4 + bytes.len())?;
    if total > CONTROL_FRAME_MAX_BYTES {
        return Err(ControlError::FrameTooLarge {
            actual: total,
            limit: CONTROL_FRAME_MAX_BYTES,
        });
    }
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn checked_extend_len(current: usize, additional: usize) -> Result<usize, ControlError> {
    current
        .checked_add(additional)
        .ok_or(ControlError::LengthOverflow)
}
