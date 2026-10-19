//! Contract, vector, boundary, and negative-path tests.

use super::payload::{append_json_string, text_violation};
use super::*;

const SESSION_BYTE: u8 = 0x11;
const LIFETIME_BYTE: u8 = 0x22;
const ACK_BYTE: u8 = 0x33;
const RECEIPT_BYTE: u8 = 0x33;
const DATA_DIGEST_BYTE: u8 = 0x77;

fn sid() -> SessionId {
    SessionId::new([SESSION_BYTE; 32])
}

fn lifetime() -> LifetimeId {
    LifetimeId::new([LIFETIME_BYTE; 32])
}

fn ack_id() -> AckId {
    AckId::new([ACK_BYTE; 32])
}

fn receipt() -> ReceiptId {
    ReceiptId::new([RECEIPT_BYTE; 32])
}

fn data_digest() -> Digest {
    Digest::new([DATA_DIGEST_BYTE; 32])
}

fn empty_payload() -> ProviderRoutingProjection {
    ProviderRoutingProjection::empty()
}

fn tuple() -> Tuple {
    Tuple::new(
        PublicationId::from_parts(sid(), 1),
        1,
        empty_payload().digest(),
    )
    .expect("valid tuple")
}

fn valid_echo() -> EstablishmentEcho {
    EstablishmentEcho {
        bootstrap_format_version: BOOTSTRAP_FORMAT_VERSION,
        control_protocol_version: CONTROL_PROTOCOL_VERSION,
        core_instance_nonce: Nonce::new([0x01; 32]),
        launch_nonce: sid(),
        component_name: "bitty-ai-helper".to_owned(),
        descriptor_version: "1.2.3".to_owned(),
        executable_name: "bitty-ai-helper".to_owned(),
        executable_sha256: Digest::new([0x02; 32]),
        component_protocol_version: 1,
        control_channel_nonce: Nonce::new([0x03; 32]),
        data_channel_nonce: Nonce::new([0x04; 32]),
        delegation_purpose: DELEGATION_PURPOSE.to_owned(),
        control_profile: CONTROL_PROFILE.to_owned(),
        key_material_profile: KEY_MATERIAL_PROFILE,
        key_type: KEY_TYPE_ECDSA_P256,
        core_leaf_digest: Digest::new([0x05; 32]),
        helper_leaf_digest: Digest::new([0x06; 32]),
    }
}

fn ack_body() -> AckBody {
    AckBody {
        lifetime_id: lifetime(),
        feed_revision: 1,
        tuple: tuple(),
        ack_id: ack_id(),
    }
}

fn valid_records() -> Vec<(Sender, RecordBody)> {
    vec![
        (Sender::Core, RecordBody::Establish(valid_echo())),
        (
            Sender::Helper,
            RecordBody::Established(EstablishedBody {
                echo: valid_echo(),
                lifetime_id: lifetime(),
            }),
        ),
        (
            Sender::Helper,
            RecordBody::Projection(ProjectionBody {
                lifetime_id: lifetime(),
                feed_revision: 1,
                payload: empty_payload(),
            }),
        ),
        (
            Sender::Core,
            RecordBody::Publish(PublishBody {
                lifetime_id: lifetime(),
                feed_revision: 1,
                tuple: tuple(),
                payload: empty_payload(),
            }),
        ),
        (Sender::Helper, RecordBody::Ack(ack_body())),
        (Sender::Core, RecordBody::Bind(ack_body())),
        (
            Sender::Helper,
            RecordBody::Bound(BoundBody {
                lifetime_id: lifetime(),
                feed_revision: 1,
                tuple: tuple(),
                receipt: receipt(),
            }),
        ),
        (
            Sender::Core,
            RecordBody::Invalidate(InvalidateBody {
                lifetime_id: lifetime(),
                feed_revision: 1,
                reason: Reason::SourceMutation,
            }),
        ),
        (
            Sender::Helper,
            RecordBody::Lifetime(LifetimeBody {
                lifetime_id: lifetime(),
                feed_revision: 1,
            }),
        ),
        (
            Sender::Core,
            RecordBody::Admit(AdmitBody {
                lifetime_id: lifetime(),
                feed_revision: 1,
                tuple: tuple(),
                receipt: receipt(),
                request_id: 1,
                data_frame_digest: data_digest(),
            }),
        ),
        (
            Sender::Helper,
            RecordBody::Admitted(AdmittedBody {
                request_id: 1,
                data_frame_digest: data_digest(),
                lifetime_id: lifetime(),
            }),
        ),
        (Sender::Core, RecordBody::Error(ErrorCode::Timeout)),
    ]
}

fn make_record(sender: Sender, body: RecordBody) -> ControlRecord {
    ControlRecord {
        sender,
        sequence: 1,
        session_id: sid(),
        body,
    }
}

fn round_trip(sender: Sender, body: RecordBody) {
    let wire = make_record(sender, body.clone());
    let bytes = wire.encode().expect("record encodes");
    let decoded = ControlRecord::decode(&bytes).expect("record decodes");
    assert_eq!(decoded, wire);
    assert_eq!(decoded.body, body);
    assert_eq!(decoded.body.kind(), wire.body.kind());
}

fn hex_decode(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex high digit");
            let low = (pair[1] as char).to_digit(16).expect("hex low digit");
            ((high << 4) | low) as u8
        })
        .collect()
}

fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("needle present")
}

// ── record round trips and the pinned Admit vector ──────────────────────────

#[test]
fn every_valid_kind_round_trips() {
    for (sender, body) in valid_records() {
        round_trip(sender, body);
    }
}

#[test]
fn reserved_kind_is_refused_both_ways() {
    let reserved = make_record(Sender::Core, RecordBody::Reserved);
    assert_eq!(reserved.encode(), Err(ControlError::ReservedKind));

    let mut bytes = make_record(Sender::Core, RecordBody::Establish(valid_echo()))
        .encode()
        .expect("valid record");
    bytes[6..8].copy_from_slice(&9u16.to_be_bytes());
    assert_eq!(
        ControlRecord::decode(&bytes),
        Err(ControlError::ReservedKind)
    );
}

#[test]
fn admit_fixture_is_the_exact_spec_vector() {
    let fixture_hex = concat!(
        "425050430001000b010000000000000004111111111111111111111111111111",
        "1111111111111111111111111111111111222222222222222222222222222222",
        "2222222222222222222222222222222222000000000000000101111111111111",
        "1111111111111111111111111111111111111111111111111111000000000000",
        "00010000000000000001c2c6d4a1a7b593a4888956ebb74b129d30e4f37fc980",
        "cb43279cbb2e26783dbb33333333333333333333333333333333333333333333",
        "333333333333333333330000000000000001b41526c9f648f9a12537daa96f98",
        "be50498c0f251d280f4210661beadf443105"
    );
    let fixture = hex_decode(fixture_hex);
    assert_eq!(fixture.len(), 242);
    assert_eq!(fixture.len(), 0xf2);

    let request = br#"{"v":1,"id":1,"method":"ai.provider_list","params":{"snapshot_version":0}}"#;
    assert_eq!(request.len(), 74);
    assert_eq!(
        Digest::of(request).to_hex(),
        "b41526c9f648f9a12537daa96f98be50498c0f251d280f4210661beadf443105"
    );

    let record = ControlRecord {
        sender: Sender::Core,
        sequence: 4,
        session_id: sid(),
        body: RecordBody::Admit(AdmitBody {
            lifetime_id: lifetime(),
            feed_revision: 1,
            tuple: tuple(),
            receipt: receipt(),
            request_id: 1,
            data_frame_digest: Digest::of(request),
        }),
    };
    assert_eq!(record.encode().expect("fixture encodes"), fixture);

    let decoded = ControlRecord::decode(&fixture).expect("fixture decodes");
    assert_eq!(decoded, record);
    assert_eq!(decoded.body.kind(), Kind::Admit);
}

#[test]
fn zero_request_id_is_representable() {
    let body = RecordBody::Admit(AdmitBody {
        lifetime_id: lifetime(),
        feed_revision: 1,
        tuple: tuple(),
        receipt: receipt(),
        request_id: 0,
        data_frame_digest: data_digest(),
    });
    round_trip(Sender::Core, body);
}

// ── fixed header ────────────────────────────────────────────────────────────

#[test]
fn header_layout_is_exact() {
    let header = RecordHeader {
        kind: Kind::Publish,
        sender: Sender::Core,
        sequence: 7,
        session_id: sid(),
    };
    let bytes = header.encode().expect("header encodes");
    assert_eq!(bytes.len(), 49);
    assert_eq!(&bytes[0..4], b"BPPC");
    assert_eq!(&bytes[4..6], &CONTROL_VERSION.to_be_bytes());
    assert_eq!(&bytes[6..8], &4u16.to_be_bytes());
    assert_eq!(bytes[8], 1);
    assert_eq!(&bytes[9..17], &7u64.to_be_bytes());
    assert_eq!(&bytes[17..49], sid().as_bytes());

    let (decoded, consumed) = RecordHeader::decode(&bytes).expect("header decodes");
    assert_eq!(consumed, 49);
    assert_eq!(decoded, header);
}

#[test]
fn header_rejects_bad_magic_version_kind_sender_and_sequence() {
    let bytes = make_record(Sender::Core, RecordBody::Establish(valid_echo()))
        .encode()
        .expect("valid record");

    let mut bad = bytes.clone();
    bad[0] = b'X';
    assert_eq!(ControlRecord::decode(&bad), Err(ControlError::InvalidMagic));

    let mut bad = bytes.clone();
    bad[4..6].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::UnsupportedVersion { actual: 2 })
    );

    for kind in [0u16, 14] {
        let mut bad = bytes.clone();
        bad[6..8].copy_from_slice(&kind.to_be_bytes());
        assert_eq!(
            ControlRecord::decode(&bad),
            Err(ControlError::UnknownKind { actual: kind })
        );
    }

    for sender in [0u8, 3] {
        let mut bad = bytes.clone();
        bad[8] = sender;
        assert_eq!(
            ControlRecord::decode(&bad),
            Err(ControlError::UnknownSender { actual: sender })
        );
    }

    let mut bad = bytes.clone();
    bad[9..17].copy_from_slice(&0u64.to_be_bytes());
    assert_eq!(ControlRecord::decode(&bad), Err(ControlError::SequenceZero));

    let mut bad = bytes;
    bad[17] = 0x12;
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::SessionMismatch)
    );
}

#[test]
fn direction_is_fixed_per_kind() {
    for (sender, body) in valid_records() {
        let kind = body.kind();
        let wrong = match sender {
            Sender::Core => Sender::Helper,
            Sender::Helper => Sender::Core,
        };
        match kind.direction() {
            Direction::Either => {
                round_trip(sender, body.clone());
                round_trip(wrong, body);
            }
            Direction::CoreToHelper | Direction::HelperToCore => {
                assert_eq!(
                    make_record(wrong, body.clone()).encode(),
                    Err(ControlError::WrongDirection {
                        kind,
                        sender: wrong
                    })
                );
                let mut bytes = make_record(sender, body).encode().expect("valid record");
                bytes[8] = wrong.code();
                assert_eq!(
                    ControlRecord::decode(&bytes),
                    Err(ControlError::WrongDirection {
                        kind,
                        sender: wrong
                    })
                );
            }
            Direction::Neither => unreachable!("valid kinds are directional"),
        }
    }
    assert_eq!(Kind::Reserved.direction(), Direction::Neither);
}

#[test]
fn establishment_fixed_fields_are_checked_on_encode_and_decode() {
    let mut echo = valid_echo();
    echo.bootstrap_format_version = 2;
    assert_eq!(
        make_record(Sender::Core, RecordBody::Establish(echo)).encode(),
        Err(ControlError::UnsupportedBootstrapVersion { actual: 2 })
    );

    let mut echo = valid_echo();
    echo.control_protocol_version = 2;
    assert_eq!(
        make_record(Sender::Core, RecordBody::Establish(echo)).encode(),
        Err(ControlError::UnsupportedControlProtocolVersion { actual: 2 })
    );

    let mut echo = valid_echo();
    echo.delegation_purpose = "other-purpose".to_owned();
    assert_eq!(
        make_record(Sender::Core, RecordBody::Establish(echo)).encode(),
        Err(ControlError::UnexpectedConstant {
            field: "delegation_purpose"
        })
    );

    let mut echo = valid_echo();
    echo.control_profile = "other-profile".to_owned();
    assert_eq!(
        make_record(Sender::Core, RecordBody::Establish(echo)).encode(),
        Err(ControlError::UnexpectedConstant {
            field: "control_profile"
        })
    );

    let mut echo = valid_echo();
    echo.key_material_profile = 2;
    assert_eq!(
        make_record(Sender::Core, RecordBody::Establish(echo)).encode(),
        Err(ControlError::UnsupportedKeyMaterialProfile { actual: 2 })
    );

    let mut echo = valid_echo();
    echo.key_type = 2;
    assert_eq!(
        make_record(Sender::Core, RecordBody::Establish(echo)).encode(),
        Err(ControlError::UnsupportedKeyType { actual: 2 })
    );

    let bytes = make_record(Sender::Core, RecordBody::Establish(valid_echo()))
        .encode()
        .expect("valid record");

    let mut bad = bytes.clone();
    bad[CONTROL_HEADER_BYTES + 4] = ROLE_HELPER;
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::InvalidRole {
            index: 0,
            actual: ROLE_HELPER
        })
    );

    let mut bad = bytes.clone();
    bad[CONTROL_HEADER_BYTES + 5] = ROLE_CORE;
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::InvalidRole {
            index: 1,
            actual: ROLE_CORE
        })
    );

    let mut bad = bytes.clone();
    bad[CONTROL_HEADER_BYTES..CONTROL_HEADER_BYTES + 2].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::UnsupportedBootstrapVersion { actual: 2 })
    );

    let mut bad = bytes.clone();
    bad[CONTROL_HEADER_BYTES + 2..CONTROL_HEADER_BYTES + 4].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::UnsupportedControlProtocolVersion { actual: 2 })
    );

    let purpose = find(&bytes, DELEGATION_PURPOSE.as_bytes());
    let mut bad = bytes.clone();
    bad[purpose] = b'X';
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::UnexpectedConstant {
            field: "delegation_purpose"
        })
    );

    let profile = find(&bytes, CONTROL_PROFILE.as_bytes());
    let mut bad = bytes.clone();
    bad[profile] = b'X';
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::UnexpectedConstant {
            field: "control_profile"
        })
    );

    let mut bad = bytes.clone();
    let key_profile = bad.len() - 66;
    bad[key_profile] = 2;
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::UnsupportedKeyMaterialProfile { actual: 2 })
    );

    let mut bad = bytes;
    let key_type = bad.len() - 65;
    bad[key_type] = 2;
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::UnsupportedKeyType { actual: 2 })
    );
}

#[test]
fn closed_reason_error_and_domain_values_are_checked() {
    let mut invalidate = make_record(
        Sender::Core,
        RecordBody::Invalidate(InvalidateBody {
            lifetime_id: lifetime(),
            feed_revision: 1,
            reason: Reason::Shutdown,
        }),
    )
    .encode()
    .expect("valid record");
    *invalidate.last_mut().expect("non-empty") = 7;
    assert_eq!(
        ControlRecord::decode(&invalidate),
        Err(ControlError::UnknownReason { actual: 7 })
    );

    let mut error = make_record(Sender::Core, RecordBody::Error(ErrorCode::Timeout))
        .encode()
        .expect("valid record");
    *error.last_mut().expect("non-empty") = 5;
    assert_eq!(
        ControlRecord::decode(&error),
        Err(ControlError::UnknownErrorCode { actual: 5 })
    );

    let mut publish = make_record(
        Sender::Core,
        RecordBody::Publish(PublishBody {
            lifetime_id: lifetime(),
            feed_revision: 1,
            tuple: tuple(),
            payload: empty_payload(),
        }),
    )
    .encode()
    .expect("valid record");
    let domain_offset = CONTROL_HEADER_BYTES + 32 + 8;
    publish[domain_offset] = 2;
    assert_eq!(
        ControlRecord::decode(&publish),
        Err(ControlError::UnknownDomain { actual: 2 })
    );
}

#[test]
fn zero_versions_and_feed_revisions_are_refused() {
    let projection = ProjectionBody {
        lifetime_id: lifetime(),
        feed_revision: 0,
        payload: empty_payload(),
    };
    assert_eq!(
        make_record(Sender::Helper, RecordBody::Projection(projection)).encode(),
        Err(ControlError::ZeroValue {
            field: "feed_revision"
        })
    );

    assert_eq!(
        Tuple::new(
            PublicationId::from_parts(sid(), 1),
            0,
            empty_payload().digest()
        ),
        Err(ControlError::ZeroValue {
            field: "snapshot_version"
        })
    );

    let tuple = Tuple {
        domain: Domain::ProviderRouting,
        publication_id: PublicationId::from_parts(sid(), 0),
        snapshot_version: 1,
        digest: empty_payload().digest(),
    };
    assert_eq!(
        make_record(
            Sender::Core,
            RecordBody::Publish(PublishBody {
                lifetime_id: lifetime(),
                feed_revision: 1,
                tuple,
                payload: empty_payload(),
            }),
        )
        .encode(),
        Err(ControlError::ZeroValue {
            field: "publication_version"
        })
    );
}

#[test]
fn digest_mismatch_is_refused_for_projection_and_publish() {
    let publish = make_record(
        Sender::Core,
        RecordBody::Publish(PublishBody {
            lifetime_id: lifetime(),
            feed_revision: 1,
            tuple: tuple(),
            payload: empty_payload(),
        }),
    )
    .encode()
    .expect("valid record");
    let digest_offset = CONTROL_HEADER_BYTES + 32 + 8 + 1 + 40 + 8;
    let mut bad = publish;
    bad[digest_offset] ^= 0xff;
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::DigestMismatch)
    );

    let projection = make_record(
        Sender::Helper,
        RecordBody::Projection(ProjectionBody {
            lifetime_id: lifetime(),
            feed_revision: 1,
            payload: empty_payload(),
        }),
    )
    .encode()
    .expect("valid record");
    let digest_offset = CONTROL_HEADER_BYTES + 32 + 8;
    let mut bad = projection;
    bad[digest_offset] ^= 0xff;
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::DigestMismatch)
    );
}

// ── truncation, trailing bytes, and declared lengths ────────────────────────

#[test]
fn every_truncated_prefix_is_rejected() {
    for (sender, body) in valid_records() {
        let kind = body.kind();
        let bytes = make_record(sender, body).encode().expect("valid record");
        for cut in 0..bytes.len() {
            assert!(
                ControlRecord::decode(&bytes[..cut]).is_err(),
                "{kind} prefix {cut} decoded unexpectedly"
            );
        }
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut bytes = make_record(Sender::Core, RecordBody::Error(ErrorCode::Unavailable))
        .encode()
        .expect("valid record");
    bytes.push(0);
    assert_eq!(
        ControlRecord::decode(&bytes),
        Err(ControlError::TrailingBytes { remaining: 1 })
    );
}

#[test]
fn string_bounds_and_truncation_are_checked() {
    let max = "a".repeat(CONTROL_STRING_MAX_BYTES);
    let mut echo = valid_echo();
    echo.component_name = max;
    make_record(Sender::Core, RecordBody::Establish(echo))
        .encode()
        .expect("128-byte string encodes");

    let mut echo = valid_echo();
    echo.component_name = "a".repeat(CONTROL_STRING_MAX_BYTES + 1);
    assert_eq!(
        make_record(Sender::Core, RecordBody::Establish(echo)).encode(),
        Err(ControlError::InvalidText {
            field: "component_name",
            reason: TextViolation::TooLong {
                limit: CONTROL_STRING_MAX_BYTES,
                actual: CONTROL_STRING_MAX_BYTES + 1
            }
        })
    );

    let mut echo = valid_echo();
    echo.component_name.clear();
    assert_eq!(
        make_record(Sender::Core, RecordBody::Establish(echo)).encode(),
        Err(ControlError::InvalidText {
            field: "component_name",
            reason: TextViolation::Empty
        })
    );

    let mut echo = valid_echo();
    echo.component_name = "line\nbreak".to_owned();
    assert_eq!(
        make_record(Sender::Core, RecordBody::Establish(echo)).encode(),
        Err(ControlError::InvalidText {
            field: "component_name",
            reason: TextViolation::ControlCharacter
        })
    );

    let bytes = make_record(Sender::Core, RecordBody::Establish(valid_echo()))
        .encode()
        .expect("valid record");
    let length_offset = CONTROL_HEADER_BYTES + 2 + 2 + 2 + 32 + 32;
    let mut bad = bytes.clone();
    bad[length_offset..length_offset + 4]
        .copy_from_slice(&(CONTROL_STRING_MAX_BYTES as u32 + 1).to_be_bytes());
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::FieldTooLarge {
            field: "component_name",
            limit: CONTROL_STRING_MAX_BYTES,
            actual: CONTROL_STRING_MAX_BYTES + 1
        })
    );

    let mut bad = bytes;
    bad[length_offset..length_offset + 4]
        .copy_from_slice(&(CONTROL_STRING_MAX_BYTES as u32).to_be_bytes());
    bad.truncate(length_offset + 4 + 10);
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::Truncated {
            field: "component_name",
            needed: CONTROL_STRING_MAX_BYTES,
            remaining: 10
        })
    );
}

#[test]
fn payload_and_frame_bounds_are_checked() {
    assert!(matches!(
        ProviderRoutingProjection::parse_canonical(&vec![0u8; CONTROL_PAYLOAD_MAX_BYTES + 1]),
        Err(PayloadError::TooLarge { .. })
    ));
    assert!(matches!(
        ProviderRoutingProjection::parse_canonical(&vec![0u8; CONTROL_PAYLOAD_MAX_BYTES]),
        Err(PayloadError::InvalidJson)
    ));

    let oversized = vec![0u8; CONTROL_FRAME_MAX_BYTES + 1];
    assert_eq!(
        ControlRecord::decode(&oversized),
        Err(ControlError::FrameTooLarge {
            actual: CONTROL_FRAME_MAX_BYTES + 1,
            limit: CONTROL_FRAME_MAX_BYTES
        })
    );

    let publish = make_record(
        Sender::Core,
        RecordBody::Publish(PublishBody {
            lifetime_id: lifetime(),
            feed_revision: 1,
            tuple: tuple(),
            payload: empty_payload(),
        }),
    )
    .encode()
    .expect("valid record");
    let payload_length_offset = CONTROL_HEADER_BYTES + 32 + 8 + 1 + 40 + 8 + 32;
    let mut bad = publish.clone();
    bad[payload_length_offset..payload_length_offset + 4]
        .copy_from_slice(&(CONTROL_PAYLOAD_MAX_BYTES as u32 + 1).to_be_bytes());
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::PayloadTooLarge {
            actual: CONTROL_PAYLOAD_MAX_BYTES + 1,
            limit: CONTROL_PAYLOAD_MAX_BYTES
        })
    );

    let mut bad = publish;
    let payload_len = empty_payload().canonical_bytes().len();
    bad[payload_length_offset..payload_length_offset + 4]
        .copy_from_slice(&(payload_len as u32).to_be_bytes());
    bad.truncate(payload_length_offset + 4 + 10);
    assert_eq!(
        ControlRecord::decode(&bad),
        Err(ControlError::Truncated {
            field: "payload",
            needed: payload_len,
            remaining: 10
        })
    );
}

#[test]
fn fixed_small_record_bound_is_respected() {
    assert_eq!(CONTROL_SMALL_RECORD_MAX_BYTES, 4096);
    assert_eq!(
        super::record::ensure_small_record(CONTROL_SMALL_RECORD_MAX_BYTES),
        Ok(())
    );
    assert_eq!(
        super::record::ensure_small_record(CONTROL_SMALL_RECORD_MAX_BYTES + 1),
        Err(ControlError::SmallRecordTooLarge {
            actual: CONTROL_SMALL_RECORD_MAX_BYTES + 1,
            limit: CONTROL_SMALL_RECORD_MAX_BYTES
        })
    );
    let mut echo = valid_echo();
    echo.component_name = "a".repeat(CONTROL_STRING_MAX_BYTES);
    echo.descriptor_version = "b".repeat(CONTROL_STRING_MAX_BYTES);
    echo.executable_name = "c".repeat(CONTROL_STRING_MAX_BYTES);
    let bytes = make_record(Sender::Core, RecordBody::Establish(echo))
        .encode()
        .expect("max-size echo encodes");
    assert!(bytes.len() <= CONTROL_SMALL_RECORD_MAX_BYTES);
    ControlRecord::decode(&bytes).expect("max-size echo decodes");
}

// ── sequence and session helpers ────────────────────────────────────────────

#[test]
fn sequence_helpers_start_at_one_and_reject_overflow() {
    assert_eq!(next_expected_sequence(0), Ok(1));
    assert_eq!(next_expected_sequence(5), Ok(6));
    assert_eq!(
        next_expected_sequence(u64::MAX),
        Err(ControlError::SequenceExhausted)
    );

    assert_eq!(validate_incoming_sequence(0, 1), Ok(()));
    assert_eq!(validate_incoming_sequence(5, 6), Ok(()));
    assert_eq!(
        validate_incoming_sequence(0, 0),
        Err(ControlError::SequenceZero)
    );
    assert_eq!(
        validate_incoming_sequence(0, 2),
        Err(ControlError::SequenceMismatch {
            expected: 1,
            received: 2
        })
    );
    assert_eq!(
        validate_incoming_sequence(5, 5),
        Err(ControlError::SequenceMismatch {
            expected: 6,
            received: 5
        })
    );
    assert_eq!(
        validate_incoming_sequence(u64::MAX, u64::MAX),
        Err(ControlError::SequenceExhausted)
    );
}

#[test]
fn session_helper_compares_exact_nonces() {
    assert_eq!(validate_session(sid(), sid()), Ok(()));
    assert_eq!(
        validate_session(sid(), SessionId::new([0x12; 32])),
        Err(ControlError::SessionMismatch)
    );
}

// ── named bound values and limit boundaries ─────────────────────────────────

#[test]
fn named_bounds_match_the_contract() {
    assert_eq!(CONTROL_FRAME_MAX_BYTES, 256 * 1024);
    assert_eq!(CONTROL_INFLIGHT_MAX_BYTES, 512 * 1024);
    assert_eq!(CONTROL_TLS_BUFFER_MAX_BYTES, 64 * 1024);
    assert_eq!(CONTROL_HANDSHAKE_MAX_BYTES, 64 * 1024);
    assert_eq!(CONTROL_SMALL_RECORD_MAX_BYTES, 4 * 1024);
    assert_eq!(CONTROL_BOOTSTRAP_MAX_BYTES, 4 * 1024);
    assert_eq!(CONTROL_PAYLOAD_MAX_BYTES, CONTROL_FRAME_MAX_BYTES - 512);
    assert_eq!(CONTROL_QUEUE_MAX_RECORDS, 2);
    assert_eq!(CONTROL_PENDING_PUBLICATIONS, 1);
    assert_eq!(CONTROL_PENDING_STRICT_REQUESTS, 1);
    assert_eq!(CONTROL_ACTIVE_RECEIPTS, 1);
    assert_eq!(CONTROL_ENDPOINT_HANDLES_MAX, 64);
    assert_eq!(CONTROL_MODELS_MAX, 64);
    assert_eq!(CONTROL_PROVIDER_GROUPS_MAX, 64);
    assert_eq!(CONTROL_CAPABILITIES_MAX, 8);
    assert_eq!(CONTROL_STRING_MAX_BYTES, 128);
    assert_eq!(CONTROL_JSON_DEPTH_MAX, 8);
    assert_eq!(LAUNCH_CERT_MAX_BYTES, 1024);
    assert_eq!(LAUNCH_KEY_MAX_BYTES, 256);
    assert_eq!(RANDOM_ID_BYTES, 32);
    assert_eq!(LIFETIME_SECRET_BYTES, 32);
    assert_eq!(CONTROL_ESTABLISH_TIMEOUT.as_secs(), 5);
    assert_eq!(CONTROL_TRANSACTION_TIMEOUT.as_secs(), 5);
    assert_eq!(CONTROL_SESSION_MAX_AGE.as_secs(), 60);
    assert_eq!(CONTROL_RECORD_RATE, 100);
    assert_eq!(CONTROL_RECORD_BURST, 200);
    assert_eq!(CONTROL_RECORD_BURST_WINDOW.as_secs(), 1);
}

fn model_named(index: usize) -> ModelEntry {
    ModelEntry::new(format!("model-{index:02}"), vec![Capability::Text], 0, 0, 0)
        .expect("valid model")
}

fn provider_named(index: usize) -> ProviderEntry {
    ProviderEntry::new(format!("provider-{index:02}"), vec![model_named(index)])
        .expect("valid provider")
}

#[test]
fn model_and_provider_bounds_are_limit_and_limit_plus_one() {
    let models: Vec<ModelEntry> = (0..CONTROL_MODELS_MAX).map(model_named).collect();
    let provider = ProviderEntry::new("bulk", models).expect("64 models");
    ProviderRoutingProjection::new(vec![provider]).expect("64 total models accepted");

    let models: Vec<ModelEntry> = (0..=CONTROL_MODELS_MAX).map(model_named).collect();
    let provider = ProviderEntry::new("bulk", models).expect("65 models fit one group");
    assert_eq!(
        ProviderRoutingProjection::new(vec![provider]),
        Err(PayloadError::TooManyModels {
            actual: CONTROL_MODELS_MAX + 1,
            limit: CONTROL_MODELS_MAX
        })
    );

    let providers: Vec<ProviderEntry> = (0..CONTROL_PROVIDER_GROUPS_MAX)
        .map(provider_named)
        .collect();
    ProviderRoutingProjection::new(providers).expect("64 groups accepted");

    let providers: Vec<ProviderEntry> = (0..=CONTROL_PROVIDER_GROUPS_MAX)
        .map(provider_named)
        .collect();
    assert_eq!(
        ProviderRoutingProjection::new(providers),
        Err(PayloadError::TooManyProviders {
            actual: CONTROL_PROVIDER_GROUPS_MAX + 1,
            limit: CONTROL_PROVIDER_GROUPS_MAX
        })
    );
}

#[test]
fn capability_and_string_bounds_are_limit_and_limit_plus_one() {
    ModelEntry::new("model", Capability::ALL.to_vec(), 0, 0, 0).expect("8 capabilities");
    assert_eq!(
        ModelEntry::new("model", vec![Capability::Text; 9], 0, 0, 0),
        Err(PayloadError::TooManyCapabilities {
            actual: 9,
            limit: CONTROL_CAPABILITIES_MAX
        })
    );

    let max = "a".repeat(CONTROL_STRING_MAX_BYTES);
    ModelEntry::new(max, vec![Capability::Text], 0, 0, 0).expect("128 bytes");
    assert_eq!(
        ModelEntry::new(
            "a".repeat(CONTROL_STRING_MAX_BYTES + 1),
            vec![Capability::Text],
            0,
            0,
            0
        ),
        Err(PayloadError::InvalidText {
            field: "model.name",
            reason: TextViolation::TooLong {
                limit: CONTROL_STRING_MAX_BYTES,
                actual: CONTROL_STRING_MAX_BYTES + 1
            }
        })
    );
}

#[test]
fn json_depth_bound_is_limit_and_limit_plus_one() {
    let at_limit_nested = format!("{}{}", "[".repeat(7), "]".repeat(7));
    let at_limit = format!(r#"{{"domain":"provider-routing","providers":{at_limit_nested}}}"#);
    let error = ProviderRoutingProjection::parse_canonical(at_limit.as_bytes())
        .expect_err("nested arrays are not a provider object");
    assert_eq!(error, PayloadError::InvalidJson);

    let over_limit_nested = format!("{}{}", "[".repeat(8), "]".repeat(8));
    let over_limit = format!(r#"{{"domain":"provider-routing","providers":{over_limit_nested}}}"#);
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(over_limit.as_bytes()),
        Err(PayloadError::JsonDepthExceeded {
            limit: CONTROL_JSON_DEPTH_MAX
        })
    );
}

// ── canonical vectors and DTO validation ────────────────────────────────────

fn model(
    name: &str,
    capabilities: Vec<Capability>,
    window: u32,
    input: u32,
    output: u32,
) -> ModelEntry {
    ModelEntry::new(name, capabilities, window, input, output).expect("valid model")
}

fn two_provider_projection() -> ProviderRoutingProjection {
    ProviderRoutingProjection::new(vec![
        ProviderEntry::new(
            "zeta",
            vec![model(
                "model-z",
                vec![Capability::ToolUse, Capability::Text],
                8192,
                2,
                3,
            )],
        )
        .expect("zeta"),
        ProviderEntry::new(
            "alpha",
            vec![model(
                "model-a",
                vec![Capability::Streaming, Capability::Text],
                4096,
                1,
                1,
            )],
        )
        .expect("alpha"),
    ])
    .expect("projection")
}

#[test]
fn empty_registry_vector_is_stable() {
    let projection = empty_payload();
    assert_eq!(
        projection.canonical_bytes(),
        br#"{"domain":"provider-routing","providers":[]}"#
    );
    assert_eq!(
        projection.digest().to_hex(),
        "c2c6d4a1a7b593a4888956ebb74b129d30e4f37fc980cb43279cbb2e26783dbb"
    );
}

#[test]
fn two_provider_vector_matches_ai_0324_baseline() {
    let projection = two_provider_projection();
    assert_eq!(
        projection.canonical_bytes(),
        br#"{"domain":"provider-routing","providers":[{"id":"alpha","models":[{"name":"model-a","capabilities":["streaming","text"],"context_window_tokens":4096,"input_cost_weight":1,"output_cost_weight":1}]},{"id":"zeta","models":[{"name":"model-z","capabilities":["text","tool_use"],"context_window_tokens":8192,"input_cost_weight":2,"output_cost_weight":3}]}]}"#
    );
    assert_eq!(
        projection.digest().to_hex(),
        "12502a3569f98452cb43ceeeb90d23b20776797b1f926646997a0990f603d286"
    );
}

#[test]
fn registration_or_constructor_order_does_not_change_bytes() {
    let reverse = ProviderRoutingProjection::new(vec![
        ProviderEntry::new(
            "alpha",
            vec![model(
                "model-a",
                vec![Capability::Text, Capability::Streaming],
                4096,
                1,
                1,
            )],
        )
        .expect("alpha"),
        ProviderEntry::new(
            "zeta",
            vec![model(
                "model-z",
                vec![Capability::ToolUse, Capability::Text],
                8192,
                2,
                3,
            )],
        )
        .expect("zeta"),
    ])
    .expect("projection");
    assert_eq!(reverse, two_provider_projection());
    assert_eq!(
        reverse.canonical_bytes(),
        two_provider_projection().canonical_bytes()
    );
}

#[test]
fn non_ascii_is_raw_and_escapes_are_shortest() {
    let projection = ProviderRoutingProjection::new(vec![
        ProviderEntry::new(
            "café",
            vec![model("mödel", vec![Capability::Text], 0, 0, 0)],
        )
        .expect("non-ASCII"),
    ])
    .expect("projection");
    let bytes = projection.canonical_bytes();
    let text = std::str::from_utf8(&bytes).expect("UTF-8");
    assert!(text.contains("\"café\""));
    assert!(text.contains("\"mödel\""));

    let escaped = text.replace("café", r"caf\u00e9");
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(escaped.as_bytes()),
        Err(PayloadError::NonCanonical)
    );

    let mut out = Vec::new();
    append_json_string(&mut out, "a\"b\\c\n\t\u{0001}é");
    assert_eq!(
        out,
        r#""a\"b\\c\n\t\u0001é""#.as_bytes(),
        "shortest canonical escapes"
    );
}

#[test]
fn quotes_and_backslashes_use_canonical_json_escapes() {
    let projection = ProviderRoutingProjection::new(vec![
        ProviderEntry::new(
            "a\"b\\c",
            vec![model("model-a", vec![Capability::Text], 0, 0, 0)],
        )
        .expect("escaped identity"),
    ])
    .expect("projection");
    let bytes = projection.canonical_bytes();
    let text = std::str::from_utf8(&bytes).expect("UTF-8");
    assert!(text.contains(r#""id":"a\"b\\c""#));
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(&bytes).expect("canonical parses"),
        projection
    );
}

#[test]
fn canonical_parser_rejects_unknown_duplicate_and_reordered_fields() {
    let valid = r#"{"domain":"provider-routing","providers":[]}"#;
    ProviderRoutingProjection::parse_canonical(valid.as_bytes()).expect("empty registry");

    let unknown = r#"{"domain":"provider-routing","providers":[],"extra":0}"#;
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(unknown.as_bytes()),
        Err(PayloadError::InvalidJson)
    );

    let duplicate = r#"{"domain":"provider-routing","domain":"provider-routing","providers":[]}"#;
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(duplicate.as_bytes()),
        Err(PayloadError::InvalidJson)
    );

    let reordered = r#"{"providers":[],"domain":"provider-routing"}"#;
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(reordered.as_bytes()),
        Err(PayloadError::InvalidJson)
    );

    let whitespace = br#"{"domain": "provider-routing","providers":[]}"#;
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(whitespace),
        Err(PayloadError::InvalidJson)
    );

    let wrong_domain = r#"{"domain":"mcp","providers":[]}"#;
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(wrong_domain.as_bytes()),
        Err(PayloadError::InvalidDomain)
    );

    let trailing = r#"{"domain":"provider-routing","providers":[]}x"#;
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(trailing.as_bytes()),
        Err(PayloadError::InvalidJson)
    );
}

fn provider_json(id: &str, models: &str) -> String {
    format!(r#"{{"id":"{id}","models":[{models}]}}"#)
}

fn model_json(name: &str, capabilities: &str) -> String {
    format!(
        r#"{{"name":"{name}","capabilities":[{capabilities}],"context_window_tokens":0,"input_cost_weight":0,"output_cost_weight":0}}"#
    )
}

fn projection_json(providers: &str) -> String {
    format!(r#"{{"domain":"provider-routing","providers":[{providers}]}}"#)
}

#[test]
fn canonical_parser_rejects_unsorted_and_duplicate_collections() {
    let zeta = provider_json("zeta", &model_json("model-z", r#""text""#));
    let alpha = provider_json("alpha", &model_json("model-a", r#""text""#));
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(
            projection_json(&format!("{zeta},{alpha}")).as_bytes()
        ),
        Err(PayloadError::NonCanonical)
    );

    let reversed_models = format!(
        "{},{}",
        model_json("model-z", r#""text""#),
        model_json("model-a", r#""text""#)
    );
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(
            projection_json(&provider_json("alpha", &reversed_models)).as_bytes()
        ),
        Err(PayloadError::NonCanonical)
    );

    let unsorted_caps = provider_json("alpha", &model_json("model-a", r#""text","streaming""#));
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(projection_json(&unsorted_caps).as_bytes()),
        Err(PayloadError::NonCanonical)
    );

    let duplicate_provider = format!(
        "{},{}",
        provider_json("alpha", &model_json("model-a", r#""text""#)),
        provider_json("alpha", &model_json("model-a", r#""text""#))
    );
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(projection_json(&duplicate_provider).as_bytes()),
        Err(PayloadError::DuplicateProvider)
    );

    let duplicate_model = provider_json(
        "alpha",
        &format!(
            "{},{}",
            model_json("model-a", r#""text""#),
            model_json("model-a", r#""text""#)
        ),
    );
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(projection_json(&duplicate_model).as_bytes()),
        Err(PayloadError::DuplicateModel)
    );

    let duplicate_cap = provider_json("alpha", &model_json("model-a", r#""text","text""#));
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(projection_json(&duplicate_cap).as_bytes()),
        Err(PayloadError::DuplicateCapability)
    );
}

#[test]
fn overlong_identity_is_rejected_at_the_bound() {
    let overlong = "a".repeat(CONTROL_STRING_MAX_BYTES + 1);
    let json = projection_json(&provider_json(
        &overlong,
        &model_json("model-a", r#""text""#),
    ));
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(json.as_bytes()),
        Err(PayloadError::InvalidText {
            field: "provider.id",
            reason: TextViolation::TooLong {
                limit: CONTROL_STRING_MAX_BYTES,
                actual: CONTROL_STRING_MAX_BYTES + 1
            }
        })
    );

    // A very long literal is refused at the 129th byte, not after scanning
    // the whole field.
    let huge = "a".repeat(260_000);
    let json = projection_json(&provider_json(&huge, &model_json("model-a", r#""text""#)));
    assert!(json.len() <= CONTROL_PAYLOAD_MAX_BYTES);
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(json.as_bytes()),
        Err(PayloadError::InvalidText {
            field: "provider.id",
            reason: TextViolation::TooLong {
                limit: CONTROL_STRING_MAX_BYTES,
                actual: CONTROL_STRING_MAX_BYTES + 1
            }
        })
    );
}

#[test]
fn long_valid_multibyte_strings_parse_at_the_bound() {
    let identity = "é".repeat(64);
    let model_name = "日".repeat(42);
    assert_eq!(identity.len(), CONTROL_STRING_MAX_BYTES);
    assert_eq!(model_name.len(), 126);

    let projection = ProviderRoutingProjection::new(vec![
        ProviderEntry::new(
            identity,
            vec![model(&model_name, vec![Capability::Text], 0, 0, 0)],
        )
        .expect("multi-byte identity"),
    ])
    .expect("projection");
    let bytes = projection.canonical_bytes();
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(&bytes).expect("canonical multi-byte payload"),
        projection
    );

    let too_long = "é".repeat(64) + "a";
    assert_eq!(too_long.len(), CONTROL_STRING_MAX_BYTES + 1);
    let json = projection_json(&provider_json(
        &too_long,
        &model_json("model-a", r#""text""#),
    ));
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(json.as_bytes()),
        Err(PayloadError::InvalidText {
            field: "provider.id",
            reason: TextViolation::TooLong {
                limit: CONTROL_STRING_MAX_BYTES,
                actual: CONTROL_STRING_MAX_BYTES + 1
            }
        })
    );
}

#[test]
fn invalid_utf8_payload_fails_closed_before_parsing() {
    let invalid = PayloadError::InvalidText {
        field: "payload",
        reason: TextViolation::InvalidUtf8,
    };
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(&[0xff]),
        Err(invalid)
    );

    let mut bytes = two_provider_projection().canonical_bytes();
    let index = find(&bytes, b"alpha");
    bytes[index] = 0xff;
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(&bytes),
        Err(invalid)
    );

    let mut bytes = two_provider_projection().canonical_bytes();
    bytes.push(0xff);
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(&bytes),
        Err(invalid)
    );
}

#[test]
fn overlong_numeric_run_is_rejected_at_the_u32_digit_bound() {
    let digits = "9".repeat(100_000);
    let json = projection_json(&provider_json(
        "alpha",
        &format!(
            r#"{{"name":"model-a","capabilities":["text"],"context_window_tokens":{digits},"input_cost_weight":0,"output_cost_weight":0}}"#
        ),
    ));
    assert!(json.len() <= CONTROL_PAYLOAD_MAX_BYTES);
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(json.as_bytes()),
        Err(PayloadError::NumberOutOfRange {
            field: "context_window_tokens"
        })
    );
}

#[test]
fn canonical_parser_enforces_collection_bounds() {
    let models = |count: usize| {
        (0..count)
            .map(|index| model_json(&format!("model-{index:02}"), r#""text""#))
            .collect::<Vec<_>>()
            .join(",")
    };

    let at_limit = provider_json("alpha", &models(CONTROL_MODELS_MAX));
    ProviderRoutingProjection::parse_canonical(projection_json(&at_limit).as_bytes())
        .expect("64 models parse");

    let over_limit = provider_json("alpha", &models(CONTROL_MODELS_MAX + 1));
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(projection_json(&over_limit).as_bytes()),
        Err(PayloadError::TooManyModels {
            actual: CONTROL_MODELS_MAX + 1,
            limit: CONTROL_MODELS_MAX
        })
    );

    let providers = |count: usize| {
        (0..count)
            .map(|index| {
                provider_json(
                    &format!("provider-{index:02}"),
                    &model_json("model-a", r#""text""#),
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    ProviderRoutingProjection::parse_canonical(projection_json(&providers(64)).as_bytes())
        .expect("64 provider groups parse");
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(projection_json(&providers(65)).as_bytes()),
        Err(PayloadError::TooManyProviders {
            actual: 65,
            limit: CONTROL_PROVIDER_GROUPS_MAX
        })
    );

    let nine_caps = provider_json(
        "alpha",
        &model_json(
            "model-a",
            r#""text","text","text","text","text","text","text","text","text""#,
        ),
    );
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(projection_json(&nine_caps).as_bytes()),
        Err(PayloadError::TooManyCapabilities {
            actual: 9,
            limit: CONTROL_CAPABILITIES_MAX
        })
    );
}

#[test]
fn canonical_parser_rejects_empty_groups_and_bad_values() {
    assert_eq!(
        ProviderEntry::new("alpha", Vec::new()),
        Err(PayloadError::EmptyProviderGroup)
    );
    assert_eq!(
        ModelEntry::new("model-a", Vec::new(), 0, 0, 0),
        Err(PayloadError::EmptyCapabilityGroup)
    );

    let empty_models = provider_json("alpha", "");
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(projection_json(&empty_models).as_bytes()),
        Err(PayloadError::EmptyProviderGroup)
    );

    let empty_caps = provider_json("alpha", &model_json("model-a", ""));
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(projection_json(&empty_caps).as_bytes()),
        Err(PayloadError::EmptyCapabilityGroup)
    );

    let unknown_cap = provider_json("alpha", &model_json("model-a", r#""bogus""#));
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(projection_json(&unknown_cap).as_bytes()),
        Err(PayloadError::UnknownCapability)
    );

    let overlong = "a".repeat(CONTROL_STRING_MAX_BYTES + 1);
    let overlong_json = provider_json(&overlong, &model_json("model-a", r#""text""#));
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(projection_json(&overlong_json).as_bytes()),
        Err(PayloadError::InvalidText {
            field: "provider.id",
            reason: TextViolation::TooLong {
                limit: CONTROL_STRING_MAX_BYTES,
                actual: CONTROL_STRING_MAX_BYTES + 1
            }
        })
    );

    let control_char = provider_json("a\\nb", &model_json("model-a", r#""text""#));
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(projection_json(&control_char).as_bytes()),
        Err(PayloadError::InvalidText {
            field: "provider.id",
            reason: TextViolation::ControlCharacter
        })
    );

    let raw_control =
        "{\"domain\":\"provider-routing\",\"providers\":[{\"id\":\"a\nb\",\"models\":[]}]}";
    assert_eq!(
        ProviderRoutingProjection::parse_canonical(raw_control.as_bytes()),
        Err(PayloadError::InvalidJson)
    );
}

#[test]
fn canonical_numbers_are_exact_u32_decimals() {
    let base = |value: &str| {
        provider_json(
            "alpha",
            &format!(
                r#"{{"name":"model-a","capabilities":["text"],"context_window_tokens":{value},"input_cost_weight":0,"output_cost_weight":0}}"#
            ),
        )
    };

    for value in ["01", "-1", "1.0", "1e2", "+1", ""] {
        assert_eq!(
            ProviderRoutingProjection::parse_canonical(projection_json(&base(value)).as_bytes()),
            Err(PayloadError::InvalidJson),
            "value {value:?}"
        );
    }

    assert_eq!(
        ProviderRoutingProjection::parse_canonical(projection_json(&base("4294967296")).as_bytes()),
        Err(PayloadError::NumberOutOfRange {
            field: "context_window_tokens"
        })
    );

    let at_max = projection_json(&base("4294967295"));
    let projection = ProviderRoutingProjection::parse_canonical(at_max.as_bytes())
        .expect("u32 max is canonical");
    assert_eq!(
        projection.providers()[0].models()[0].context_window_tokens(),
        u32::MAX
    );
}

// ── closed vocabularies and fixed identifiers ───────────────────────────────

#[test]
fn closed_vocabularies_round_trip_their_codes() {
    for code in 1u16..=13 {
        let kind = Kind::from_code(code).expect("known kind");
        assert_eq!(kind.code(), code);
    }
    assert_eq!(Kind::from_code(0), None);
    assert_eq!(Kind::from_code(14), None);
    assert_eq!(Kind::Reserved.code(), 9);
    assert_eq!(Kind::Reserved.direction(), Direction::Neither);

    for code in 1u8..=6 {
        let reason = Reason::from_code(code).expect("known reason");
        assert_eq!(reason.code(), code);
    }
    assert_eq!(Reason::from_code(0), None);
    assert_eq!(Reason::from_code(7), None);

    for code in 1u8..=4 {
        let error = ErrorCode::from_code(code).expect("known error");
        assert_eq!(error.code(), code);
        assert!(!error.diagnostic().is_empty());
    }
    assert_eq!(ErrorCode::from_code(0), None);
    assert_eq!(ErrorCode::from_code(5), None);

    assert_eq!(Domain::from_code(1), Some(Domain::ProviderRouting));
    assert_eq!(Domain::from_code(0), None);
    assert_eq!(Domain::from_code(2), None);

    assert_eq!(Sender::from_code(1), Some(Sender::Core));
    assert_eq!(Sender::from_code(2), Some(Sender::Helper));
    assert_eq!(Sender::from_code(0), None);
    assert_eq!(Sender::from_code(3), None);

    assert_eq!(Capability::ALL.len(), CONTROL_CAPABILITIES_MAX);
    for capability in Capability::ALL {
        assert_eq!(Capability::from_label(capability.label()), Some(capability));
    }
    assert_eq!(
        Capability::from_label("video_input"),
        Some(Capability::VideoInput)
    );
    assert_eq!(Capability::from_label("bogus"), None);
    assert_eq!(
        Capability::ALL.map(Capability::label),
        [
            "audio_input",
            "audio_output",
            "image_input",
            "reasoning",
            "streaming",
            "text",
            "tool_use",
            "video_input",
        ]
    );
    assert!(text_violation("").is_some());
}

#[test]
fn publication_identity_is_nonce_then_big_endian_version() {
    let identity = PublicationId::from_parts(sid(), 1);
    assert_eq!(identity.launch_nonce(), sid());
    assert_eq!(identity.version(), 1);
    assert_eq!(
        identity.as_bytes(),
        &[
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        ]
    );
    assert_eq!(identity.to_hex().len(), 80);
    assert!(identity.to_hex().ends_with("0000000000000001"));
}

#[test]
fn sha256_known_vectors() {
    assert_eq!(
        Digest::of(b"").to_hex(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        Digest::of(b"abc").to_hex(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
