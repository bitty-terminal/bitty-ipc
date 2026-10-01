use super::handlers::{live_input_store, parse_optional_uint_param};
#[cfg(unix)]
use super::serve::{
    serve_bound_connection_with_test_identity, serve_connection, transport_attested_peer,
};
use super::*;
#[cfg(unix)]
use crate::auth::DIR_MODE;
#[cfg(unix)]
use crate::error::IpcError;
use crate::frame::{MAX_FRAME_BYTES, encode_frame};
#[cfg(unix)]
use crate::limits::RateLimiter;
#[cfg(unix)]
use crate::peer::StreamIdentity;
use crate::wire::MAX_JSON_DEPTH;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};

fn test_server_info() -> ServerInfo {
    ServerInfo::new(
        "test-inst".to_string(),
        "/run/user/1000/bitty/test-inst.sock".to_string(),
        80,
        24,
    )
}

fn test_context() -> ServeContext {
    // Connection alone grants no debug scope (P0-AC-025); the read-surface
    // tests model a peer that has been granted `debug.inspect`.
    let mut granted = crate::scope::ScopeSet::cli_default();
    granted.insert(crate::scope::Scope::DebugInspect);
    ServeContext::with_granted_for_tests(&test_server_info(), granted)
}

// ── socket path ─────────────────────────────────────────────────────

#[test]
fn socket_path_bitty_socket_wins_verbatim() {
    let path =
        resolve_socket_path(1000, Some("/run/user/1000"), Some("/tmp/custom.sock"), None).unwrap();
    assert_eq!(path, "/tmp/custom.sock");
}

#[test]
fn socket_path_xdg_plus_instance() {
    let path = resolve_socket_path(1000, Some("/run/user/1000"), None, Some("my-inst_1")).unwrap();
    assert_eq!(path, "/run/user/1000/bitty/my-inst_1.sock");
}

#[test]
fn socket_path_defaults() {
    let path = resolve_socket_path(1000, None, None, None).unwrap();
    assert_eq!(path, "/run/user/1000/bitty/default.sock");
}

#[test]
fn socket_path_empty_socket_falls_through() {
    let path = resolve_socket_path(1000, Some("/run/user/1000"), Some(""), None).unwrap();
    assert_eq!(path, "/run/user/1000/bitty/default.sock");
}

#[test]
fn socket_path_rejects_long_and_nul() {
    let long = "a".repeat(MAX_SOCKET_PATH_BYTES + 1);
    assert!(resolve_socket_path(1000, None, Some(&long), None).is_err());
    assert!(resolve_socket_path(1000, None, Some("/tmp/a\0b.sock"), None).is_err());
}

#[test]
fn socket_path_portable_bound_is_pinned() {
    // Portable AF_UNIX ceiling: 100 payload bytes fits Linux 108 and
    // macOS/BSD 104 incl. NUL with margin (historical floor 92).
    const { assert!(MAX_SOCKET_PATH_BYTES <= 100) };
    const { assert!(SUN_LEN_LINUX == 108) };
    const { assert!(SUN_LEN_MACOS == 104) };
    const { assert!(MAX_SOCKET_PATH_BYTES < SUN_LEN_MACOS) };
    // Every resolved path fits the portable bound incl. NUL.
    let path = resolve_socket_path(1000, Some("/run/user/1000"), None, None).unwrap();
    assert!(path.len() <= MAX_SOCKET_PATH_BYTES);
    assert!(path.len() < SUN_LEN_MACOS);
}

#[test]
fn socket_path_hashes_long_instance_to_fit() {
    // A 64-char instance with a medium base overflows direct form but
    // fits via deterministic hash clamping.
    let base = format!("/tmp/{}", "b".repeat(50));
    let long_instance = "c".repeat(MAX_INSTANCE_ID_LEN);
    let direct_len =
        base.len() + 1 + SOCKET_LEAF_DIR.len() + 1 + long_instance.len() + ".sock".len();
    assert!(direct_len > MAX_SOCKET_PATH_BYTES);
    let path = resolve_socket_path(1000, Some(&base), None, Some(&long_instance)).unwrap();
    assert!(path.len() <= MAX_SOCKET_PATH_BYTES);
    assert!(!path.contains(&long_instance));
    assert!(path.ends_with(".sock"));
    // Deterministic: same instance hashes identically.
    let again = resolve_socket_path(1000, Some(&base), None, Some(&long_instance)).unwrap();
    assert_eq!(path, again);
}

#[test]
fn socket_path_rejects_long_base_fail_closed() {
    // Even the hashed leaf cannot save a base dir that is itself too long.
    let base = format!("/tmp/{}", "d".repeat(120));
    let err = resolve_socket_path(1000, Some(&base), None, None).unwrap_err();
    let reason = format!("{err}");
    assert!(reason.contains("AF_UNIX") || reason.contains("too long"));
    let long_socket = format!("/tmp/{}.sock", "e".repeat(120));
    assert!(resolve_socket_path(1000, None, Some(&long_socket), None).is_err());
}

#[test]
fn socket_path_rejects_bad_instance() {
    assert!(resolve_socket_path(1000, None, None, Some("bad/id")).is_err());
    assert!(resolve_socket_path(1000, None, None, Some("")).is_err());
    let long = "a".repeat(MAX_INSTANCE_ID_LEN + 1);
    assert!(resolve_socket_path(1000, None, None, Some(&long)).is_err());
    assert!(resolve_socket_path(1000, None, None, Some("has space")).is_err());
}

#[test]
fn socket_path_from_env_needs_base_without_uid() {
    let env = SocketEnv::default();
    assert!(resolve_socket_path_from_env(&env, None).is_err());
    let (path, instance) = resolve_socket_path_from_env(&env, Some(1000)).unwrap();
    assert_eq!(path, "/run/user/1000/bitty/default.sock");
    assert_eq!(instance, "default");
}

#[test]
fn socket_path_from_env_socket_override() {
    let env = SocketEnv {
        bitty_socket: Some("/tmp/x.sock".to_string()),
        xdg_runtime_dir: None,
        instance_id: Some("ignored".to_string()),
    };
    let (path, instance) = resolve_socket_path_from_env(&env, None).unwrap();
    assert_eq!(path, "/tmp/x.sock");
    assert_eq!(instance, "ignored");
}

// ── windows pipe naming (CTX-0196) ──────────────────────────────────

#[test]
fn windows_pipe_name_maps_instance_verbatim() {
    assert_eq!(
        windows_pipe_name("default"),
        r"\\.\pipe\bitty-default".to_string()
    );
    assert_eq!(
        windows_pipe_name("my-inst_1"),
        r"\\.\pipe\bitty-my-inst_1".to_string()
    );
}

#[test]
fn windows_pipe_name_roundtrips_through_parser() {
    for id in ["default", "a", "my-inst_1", "ABC-9_z"] {
        let pipe = windows_pipe_name(id);
        let file = pipe.rsplit('\\').next().unwrap();
        assert_eq!(windows_instance_from_pipe_name(file).as_deref(), Some(id));
    }
}

#[test]
fn windows_pipe_parser_skips_foreign_and_malformed() {
    assert_eq!(windows_instance_from_pipe_name("bitty-"), None);
    assert_eq!(windows_instance_from_pipe_name("other-pipe"), None);
    assert_eq!(windows_instance_from_pipe_name(""), None);
    assert_eq!(windows_instance_from_pipe_name("bitty-has space"), None);
    assert_eq!(windows_instance_from_pipe_name("bitty-bad/id"), None);
    assert_eq!(windows_instance_from_pipe_name("BITTY-default"), None);
    let long = format!("bitty-{}", "a".repeat(MAX_INSTANCE_ID_LEN + 1));
    assert_eq!(windows_instance_from_pipe_name(&long), None);
    // Pipe names never carry the socket suffix.
    assert_eq!(windows_instance_from_pipe_name("bitty-default.sock"), None);
}

// ── parsing ─────────────────────────────────────────────────────────

#[test]
fn parse_transport_shape_without_jsonrpc() {
    let payload = br#"{"id":1,"method":"bitty.debug/ping","params":{},"version":"1.0"}"#;
    let request = parse_request(payload).unwrap();
    assert_eq!(request.id_raw, "1");
    assert_eq!(request.method, "bitty.debug/ping");
    assert!(!request.has_jsonrpc);
}

#[test]
fn parse_protocol_shape_with_jsonrpc() {
    let payload =
        br#"{"jsonrpc":"2.0","id":42,"method":"bitty.debug/getSnapshot","version":"1.0"}"#;
    let request = parse_request(payload).unwrap();
    assert_eq!(request.id_raw, "42");
    assert_eq!(request.method, "bitty.debug/getSnapshot");
    assert!(request.has_jsonrpc);
}

#[test]
fn parse_rejects_wrong_version_with_id() {
    let payload = br#"{"id":7,"method":"bitty.debug/ping","version":"2.0"}"#;
    let fault = parse_request(payload).unwrap_err();
    assert_eq!(fault.code, "UnsupportedVersion");
    assert_eq!(fault.id_raw.as_deref(), Some("7"));
}

#[test]
fn parse_rejects_missing_version() {
    let payload = br#"{"id":7,"method":"bitty.debug/ping"}"#;
    let fault = parse_request(payload).unwrap_err();
    assert_eq!(fault.code, "MissingVersion");
}

#[test]
fn parse_rejects_unprefixed_method() {
    let payload = br#"{"id":1,"method":"terminal.text","version":"1.0"}"#;
    let fault = parse_request(payload).unwrap_err();
    assert_eq!(fault.code, "InvalidMethod");
}

#[test]
fn parse_rejects_string_id() {
    let payload = br#"{"id":"1","method":"bitty.debug/ping","version":"1.0"}"#;
    let fault = parse_request(payload).unwrap_err();
    assert_eq!(fault.code, "MissingId");
}

#[test]
fn parse_rejects_ambient_authority() {
    let payload = br#"{"id":1,"method":"bitty.debug/ping","version":"1.0","scope":"admin"}"#;
    let fault = parse_request(payload).unwrap_err();
    assert_eq!(fault.code, "ForbiddenField");
    assert_eq!(fault.id_raw.as_deref(), Some("1"));
}

#[test]
fn parse_allows_nested_scope_in_params() {
    let payload =
        br#"{"id":1,"method":"bitty.debug/ping","version":"1.0","params":{"scope":"value"}}"#;
    assert!(parse_request(payload).is_ok());
}

#[test]
fn parse_rejects_non_object_and_garbage() {
    assert!(parse_request(br#"[1,2]"#).is_err());
    assert!(parse_request(b"not json").is_err());
    assert!(parse_request(b"").is_err());
    assert!(parse_request(&[0xFF, 0xFE]).is_err());
}

#[test]
fn parse_rejects_bad_jsonrpc() {
    let payload = br#"{"jsonrpc":"1.0","id":1,"method":"bitty.debug/ping","version":"1.0"}"#;
    let fault = parse_request(payload).unwrap_err();
    assert_eq!(fault.code, "InvalidJsonRpc");
}

#[test]
fn parse_accepts_escaped_method() {
    let payload = br#"{"id":1,"method":"bitty.debug\u002fping","version":"1.0"}"#;
    let request = parse_request(payload).unwrap();
    assert_eq!(request.method, "bitty.debug/ping");
}

#[test]
fn parse_rejects_deep_nesting() {
    let nested = "[".repeat(MAX_JSON_DEPTH + 1) + &"]".repeat(MAX_JSON_DEPTH + 1);
    assert!(parse_request(nested.as_bytes()).is_err());
}

// ── dispatch ────────────────────────────────────────────────────────

#[test]
fn dispatch_ping_round_trip() {
    let dispatcher = Dispatcher::with_defaults();
    let context = test_context();
    let outcome = handle_envelope(
        br#"{"id":3,"method":"bitty.debug/ping","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("\"id\":3"));
    assert!(text.contains("\"ok\":true"));
    assert!(text.contains("\"version\":\"1.0\""));
    assert!(text.contains("\"jsonrpc\":\"2.0\""));
}

#[test]
fn dispatch_snapshot_carries_stats() {
    let dispatcher = Dispatcher::with_defaults();
    let context = test_context();
    let outcome = handle_envelope(
        br#"{"jsonrpc":"2.0","id":9,"method":"bitty.debug/getSnapshot","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("\"id\":9"));
    assert!(text.contains("\"snapshot\":\"runtime-stats\""));
    assert!(text.contains("\"instance\":\"test-inst\""));
    assert!(text.contains("\"cols\":80"));
    assert!(text.contains("\"rows\":24"));
}

#[test]
fn dispatch_unknown_method_is_error() {
    let dispatcher = Dispatcher::with_defaults();
    let context = test_context();
    let outcome = handle_envelope(
        br#"{"id":1,"method":"bitty.debug/nope","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("UnknownMethod"));
    assert!(text.contains("\"id\":1"));
}

#[test]
fn version_mismatch_is_correlated_error() {
    let dispatcher = Dispatcher::with_defaults();
    let context = test_context();
    let outcome = handle_envelope(
        br#"{"id":11,"method":"bitty.debug/ping","version":"9.9"}"#,
        &dispatcher,
        &context,
    );
    assert!(outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("UnsupportedVersion"));
    assert!(text.contains("\"id\":11"));
}

#[test]
fn dispatcher_test_mode_registers_surface_only_when_enabled() {
    let default = Dispatcher::with_defaults();
    assert!(!default.contains(METHOD_TEST_INFO));
    assert!(!default.contains(METHOD_TEST_EXIT));
    let test_mode = Dispatcher::with_test_mode();
    assert!(test_mode.contains(METHOD_TEST_INFO));
    assert!(test_mode.contains(METHOD_TEST_EXIT));
    assert_eq!(
        test_mode.method_count(),
        default.method_count() + 2,
        "test mode must add exactly the two test-surface methods"
    );
    for method in crate::ctl::all_test_mode_control_methods() {
        assert!(
            test_mode.contains(method),
            "test-mode control method {method} must be registered"
        );
    }
}

#[test]
fn test_info_is_default_deny_without_test_mode() {
    // Registration is the gate: a normal instance answers NotFound (not a
    // scope error, not a fabricated success).
    let dispatcher = Dispatcher::with_defaults();
    let outcome = handle_envelope(
        br#"{"id":7,"method":"bitty.debug/testInfo","version":"1.0"}"#,
        &dispatcher,
        &test_context(),
    );
    assert!(
        outcome.was_error,
        "testInfo must be denied without test mode"
    );
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(
        text.contains("\"id\":7") && text.contains("UnknownMethod"),
        "denial must be a correlated UnknownMethod: {text}"
    );
}

#[test]
fn test_info_reports_e2e_surface_in_test_mode() {
    let dispatcher = Dispatcher::with_test_mode();
    let outcome = handle_envelope(
        br#"{"id":8,"method":"bitty.debug/testInfo","version":"1.0"}"#,
        &dispatcher,
        &test_context(),
    );
    assert!(!outcome.was_error, "testInfo must serve in test mode");
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(
        text.contains("\"test_mode\":true")
            && text.contains("\"surface\":\"e2e\"")
            && text.contains("\"protocol\":\"1.0\"")
            && text.contains("\"instance\":\"test-inst\""),
        "testInfo must identify the surface and instance: {text}"
    );
}

#[test]
fn test_exit_is_default_deny_without_test_mode() {
    let dispatcher = Dispatcher::with_defaults();
    let outcome = handle_envelope(
        br#"{"id":9,"method":"bitty.debug/testExit","version":"1.0"}"#,
        &dispatcher,
        &test_context(),
    );
    assert!(
        outcome.was_error,
        "testExit must be denied without test mode"
    );
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(
        text.contains("UnknownMethod"),
        "normal instances must answer NotFound, never ScopeDenied: {text}"
    );
}

#[test]
fn dispatcher_registers_new_methods_for_follow_up() {
    fn custom(context: &ServeContext, _request: &DevtoolsRequest) -> Result<String, HandlerError> {
        Ok(format!("{{\"uptime_ms\":{}}}", context.uptime_ms))
    }
    let mut dispatcher = Dispatcher::with_defaults();
    // CTX-0144 (ping, getSnapshot) plus CTX-0159 introspection
    // (getGridText, getInputRing, getModifiers, getFocus) plus CTX-0171
    // control (listWindows, listViews, listTerminals, spawnTerminal,
    // closeTerminal, sendInput, getTerminalText, splitView, focusView,
    // reloadConfig) plus CTX-0257 workspace entry (listWorkspaces,
    // createWorkspace, closeWorkspace, focusWorkspace) plus CTX-0259 move
    // (moveWorkspace) plus CTX-0188
    // automation (synthesizeInput,
    // captureFrame) plus CTX-0244 digest (frameHash) plus DT-03 trace
    // lifecycle (startTrace, stopTrace, fetchTraceChunk) plus CTX-0189
    // profiling (getProcessStats, getFrameStats, streamProcessStats,
    // streamFrameStats) plus issue #1377 plugin-runtime v1 (listPlugins,
    // getPlugin, listSubscriptions, getBudgets, getQueueSnapshot,
    // listHandles, streamEvents, suspendHandler, resumePlugin,
    // disposeGeneration).
    assert_eq!(dispatcher.method_count(), 43);
    assert!(dispatcher.contains("bitty.debug/getGridText"));
    assert!(dispatcher.contains("bitty.debug/getInputRing"));
    assert!(dispatcher.contains("bitty.debug/getModifiers"));
    assert!(dispatcher.contains("bitty.debug/getFocus"));
    assert!(dispatcher.contains(METHOD_SYNTHESIZE_INPUT));
    assert!(dispatcher.contains(METHOD_CAPTURE_FRAME));
    assert!(dispatcher.contains(METHOD_FRAME_HASH));
    assert!(dispatcher.contains(METHOD_START_TRACE));
    assert!(dispatcher.contains(METHOD_STOP_TRACE));
    assert!(dispatcher.contains(METHOD_FETCH_TRACE_CHUNK));
    assert!(dispatcher.contains(METHOD_GET_PROCESS_STATS));
    assert!(dispatcher.contains(METHOD_GET_FRAME_STATS));
    assert!(dispatcher.contains(METHOD_STREAM_PROCESS_STATS));
    assert!(dispatcher.contains(METHOD_STREAM_FRAME_STATS));
    for method in crate::ctl::all_control_methods() {
        assert!(
            dispatcher.contains(method),
            "control method {method} must be registered"
        );
    }
    dispatcher
        .register("bitty.debug/customProbe", custom)
        .unwrap();
    assert!(dispatcher.contains("bitty.debug/customProbe"));
    let context = test_context();
    let outcome = handle_envelope(
        br#"{"id":1,"method":"bitty.debug/customProbe","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    assert!(dispatcher.register("terminal.text", custom).is_err());
}

#[test]
fn error_message_truncated_to_bound() {
    let long = "x".repeat(MAX_ERROR_MESSAGE_CHARS + 100);
    let bytes = encode_error("1", "usage", "InvalidRequest", &long);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.len() < long.len() + 200);
    assert!(text.contains("..."));
}

#[test]
fn id_zero_error_shape() {
    let bytes = id_zero_error("transport", "FrameTooLarge", "too big");
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("\"id\":0"));
    assert!(text.contains("FrameTooLarge"));
}

// ── connection serving (unix socketpair, no listener) ───────────────

#[cfg(unix)]
#[test]
fn serve_connection_ping_pong_over_socketpair() {
    use std::os::unix::net::UnixStream;

    let (mut client, mut server) = UnixStream::pair().unwrap();
    let dispatcher = Dispatcher::with_defaults();
    let context = test_context();
    // Socketpair has no filesystem endpoint to attest: use the headless
    // peer-UID check directly (same marker type the accept boundary mints
    // after endpoint verification).
    let peer = crate::auth::verify_peer_for_connection(
        crate::auth::PeerCredentials::new(1000, 1000, 1),
        1000,
    )
    .unwrap();
    let mut limiter = RateLimiter::rc9_default();
    let clock = || 0u64;

    let handle = std::thread::spawn(move || {
        serve_connection(
            &mut server,
            peer,
            &dispatcher,
            &context,
            &mut limiter,
            &clock,
        )
    });

    let payload = br#"{"id":1,"method":"bitty.debug/ping","version":"1.0"}"#;
    let wire = encode_frame(payload).unwrap();
    client.write_all(&wire).unwrap();

    let mut header = [0u8; 4];
    client.read_exact(&mut header).unwrap();
    let len = u32::from_be_bytes(header) as usize;
    assert!(len <= MAX_FRAME_BYTES);
    let mut body = vec![0u8; len];
    client.read_exact(&mut body).unwrap();
    let text = String::from_utf8(body).unwrap();
    assert!(text.contains("\"ok\":true"));

    drop(client);
    let stats = handle.join().unwrap().unwrap();
    assert_eq!(stats.requests, 1);
    assert_eq!(stats.responses, 1);
    assert_eq!(stats.denied, 0);
}

#[cfg(unix)]
#[test]
fn serve_path_takes_verified_marker_only() {
    use crate::auth::{PeerCredentials, verify_peer_for_connection};
    // Regression for CodeQL HIGH `cleartext logging of sensitive
    // information`: `serve_connection` takes only the pre-verified
    // `VerifiedPeer` marker, so no `PeerCredentials`-typed value flows
    // into the serving path. Accept-boundary verification is fail-closed.
    let good = PeerCredentials::new(1000, 1000, 1);
    let verified = verify_peer_for_connection(good, 1000).unwrap();

    // Endpoint attestation on a properly owned 0700/0600 socket mints the
    // same marker type (unit euid owns the temp endpoint it just created).
    let (attested, euid) = {
        use std::os::unix::fs::PermissionsExt;
        let base =
            std::env::temp_dir().join(format!("bitty-ctx0463-{}-marker", std::process::id()));
        let socket_path = base.join("bitty/m.sock");
        let socket_str = socket_path.to_str().unwrap().to_string();
        let _dir = prepare_socket_dir(&socket_str).unwrap();
        // Bind then enforce 0600 like the servo does via attest_bound_socket.
        let listener = std::os::unix::net::UnixListener::bind(&socket_str).unwrap();
        std::fs::set_permissions(&socket_str, std::fs::Permissions::from_mode(0o600)).unwrap();
        let euid = {
            use std::os::unix::fs::MetadataExt;
            std::fs::symlink_metadata(&socket_str).unwrap().uid()
        };
        let marker = transport_attested_peer(&socket_str, euid).unwrap();
        drop(listener);
        std::fs::remove_dir_all(&base).ok();
        (marker, euid)
    };
    // CTX-0656: the attested marker binds the endpoint UID — it equals the
    // headless-verified marker for the same UID (no hardcoded UID assumed)
    // and carries that UID for downstream comparison.
    assert_eq!(attested.peer_uid(), euid);
    let headless_same =
        verify_peer_for_connection(PeerCredentials::new(euid, euid, 1), euid).unwrap();
    assert_eq!(headless_same, attested);

    // Foreign UID cannot produce a marker: rejected before any byte read.
    let foreign = PeerCredentials::new(2000, 2000, 99);
    let err = verify_peer_for_connection(foreign, 1000).unwrap_err();
    assert!(matches!(err, IpcError::Unauthenticated { .. }));

    // Verified marker serves correctly over a socketpair.
    use std::os::unix::net::UnixStream;

    let (mut client, mut server) = UnixStream::pair().unwrap();
    let dispatcher = Dispatcher::with_defaults();
    let context = test_context();
    let mut limiter = RateLimiter::rc9_default();
    let clock = || 0u64;
    let handle = std::thread::spawn(move || {
        serve_connection(
            &mut server,
            verified,
            &dispatcher,
            &context,
            &mut limiter,
            &clock,
        )
    });
    let payload = br#"{"id":1,"method":"bitty.debug/ping","version":"1.0"}"#;
    let wire = encode_frame(payload).unwrap();
    client.write_all(&wire).unwrap();
    let mut header = [0u8; 4];
    client.read_exact(&mut header).unwrap();
    let len = u32::from_be_bytes(header) as usize;
    let mut body = vec![0u8; len];
    client.read_exact(&mut body).unwrap();
    assert!(String::from_utf8(body).unwrap().contains("\"ok\":true"));
    drop(client);
    let stats = handle.join().unwrap().unwrap();
    assert_eq!(stats.requests, 1);
}

#[cfg(unix)]
#[test]
fn connected_peer_initial_mismatch_is_rejected_before_read() {
    use std::collections::VecDeque;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let peer = crate::auth::verify_peer_for_connection(
        crate::auth::PeerCredentials::new(1000, 1000, 1),
        1000,
    )
    .unwrap();
    let foreign = crate::auth::verify_peer_for_connection(
        crate::auth::PeerCredentials::new(2000, 2000, 2),
        1000,
    );
    let (_client, mut server) = UnixStream::pair().unwrap();
    server
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let sequence = Arc::new(Mutex::new(VecDeque::from([Ok(peer), foreign])));
    let mut context = ServeContext::new(&test_server_info());
    context
        .bind_connected_stream_for_test(&server, move |_| {
            sequence
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Err(IpcError::Unavailable {
                    reason: "peer fixture exhausted".into(),
                }))
        })
        .unwrap();
    let dispatcher = Dispatcher::with_defaults();
    let mut limiter = RateLimiter::rc9_default();
    let clock = || 0u64;
    let result = serve_connection(
        &mut server,
        peer,
        &dispatcher,
        &context,
        &mut limiter,
        &clock,
    );
    assert!(matches!(result, Err(IpcError::Unauthenticated { .. })));
}

#[cfg(unix)]
#[test]
fn connected_peer_binding_rejects_identity_replacement() {
    use std::collections::VecDeque;
    use std::os::unix::net::UnixStream;

    let peer = crate::auth::verify_peer_for_connection(
        crate::auth::PeerCredentials::new(1000, 1000, 1),
        1000,
    )
    .unwrap();
    let foreign = crate::auth::verify_peer_for_connection(
        crate::auth::PeerCredentials::new(2000, 2000, 2),
        2000,
    )
    .unwrap();
    let (_client, server) = UnixStream::pair().unwrap();
    let sequence = Arc::new(Mutex::new(VecDeque::from([Ok(peer), Ok(foreign)])));
    let mut context = ServeContext::new(&test_server_info());
    context
        .bind_connected_stream_for_test(&server, move |_| {
            sequence.lock().unwrap().pop_front().unwrap()
        })
        .unwrap();
    let err = context.recheck_before_dispatch().unwrap_err();
    assert!(matches!(err, IpcError::Unauthenticated { .. }));
}

#[cfg(unix)]
#[test]
fn bound_connection_rejects_a_different_accepted_stream() {
    use std::os::unix::net::UnixStream;

    let (_client_a, stream_a) = UnixStream::pair().unwrap();
    let (_client_b, mut stream_b) = UnixStream::pair().unwrap();
    let mut context = ServeContext::new(&test_server_info());
    let proof = context.bind_connected_stream_current(&stream_a).unwrap();
    let dispatcher = Dispatcher::with_defaults();
    let mut limiter = RateLimiter::rc9_default();
    let clock = || 0u64;
    let err = serve_bound_connection(
        &mut stream_b,
        &proof,
        &dispatcher,
        &context,
        &mut limiter,
        &clock,
    )
    .unwrap_err();
    assert!(matches!(err, IpcError::Unauthenticated { .. }));
}

#[cfg(unix)]
const FD_REUSE_ATTEMPT_BUDGET: usize = 64;
#[cfg(unix)]
const FD_REUSE_TIME_BUDGET: std::time::Duration = std::time::Duration::from_millis(100);

#[cfg(unix)]
fn bounded_fd_reuse(
    original_fd: std::os::fd::RawFd,
) -> Option<(
    std::os::unix::net::UnixStream,
    std::os::unix::net::UnixStream,
)> {
    let deadline = std::time::Instant::now() + FD_REUSE_TIME_BUDGET;
    for _ in 0..FD_REUSE_ATTEMPT_BUDGET {
        if std::time::Instant::now() >= deadline {
            break;
        }
        let candidate = std::os::unix::net::UnixStream::pair().ok()?;
        if candidate.0.as_raw_fd() == original_fd {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
#[test]
fn bound_connection_rejects_fd_reuse_for_a_different_stream() {
    use std::os::unix::net::UnixStream;

    let (_client_a, stream_a) = UnixStream::pair().unwrap();
    let original_fd = stream_a.as_raw_fd();
    let mut context = ServeContext::new(&test_server_info());
    let proof = context.bind_connected_stream_current(&stream_a).unwrap();
    drop(stream_a);

    let dispatcher = Dispatcher::with_defaults();
    let mut limiter = RateLimiter::rc9_default();
    let clock = || 0u64;
    let result = if let Some((mut replacement, _replacement_peer)) = bounded_fd_reuse(original_fd) {
        serve_bound_connection(
            &mut replacement,
            &proof,
            &dispatcher,
            &context,
            &mut limiter,
            &clock,
        )
    } else {
        let (mut replacement, _replacement_peer) = UnixStream::pair().unwrap();
        let original_identity = proof.stream_identity_for_test();
        let synthetic_identity = StreamIdentity {
            device: original_identity.device,
            inode: original_identity.inode.wrapping_add(1),
        };
        serve_bound_connection_with_test_identity(
            &mut replacement,
            &proof,
            &dispatcher,
            &context,
            &mut limiter,
            &clock,
            |_| Ok(synthetic_identity),
        )
    };
    assert!(matches!(result, Err(IpcError::Unauthenticated { .. })));
}

#[test]
fn replaced_ping_and_test_info_still_require_connected_peer() {
    fn custom_handler(
        _context: &ServeContext,
        _request: &DevtoolsRequest,
    ) -> Result<String, HandlerError> {
        Ok("{\"custom\":true}".to_string())
    }

    let mut dispatcher = Dispatcher::with_test_mode();
    dispatcher
        .register("bitty.debug/ping", custom_handler)
        .unwrap();
    dispatcher
        .register("bitty.debug/testInfo", custom_handler)
        .unwrap();
    let context = ServeContext::with_granted(&test_server_info(), crate::scope::ScopeSet::all());

    for method in ["bitty.debug/ping", "bitty.debug/testInfo"] {
        let request = DevtoolsRequest {
            id_raw: "1".into(),
            method: method.into(),
            has_jsonrpc: false,
            params_raw: None,
        };
        let error = dispatcher.dispatch(&context, &request).unwrap_err();
        assert_eq!(error.code, "Unauthenticated");
    }
}

#[cfg(unix)]
#[test]
fn auth_recheck_failure_closes_the_bound_connection() {
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let peer = crate::auth::verify_peer_for_connection(
        crate::auth::PeerCredentials::new(1000, 1000, 1),
        1000,
    )
    .unwrap();
    let (mut client, mut server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let sequence = Arc::new(Mutex::new(VecDeque::from([
        Ok(peer),
        Err(IpcError::Unauthenticated {
            reason: "synthetic recheck mismatch".into(),
        }),
    ])));
    let mut granted = crate::scope::ScopeSet::new();
    granted.insert(crate::scope::Scope::DebugInspect);
    let mut context = ServeContext::with_granted(&test_server_info(), granted);
    let proof = context
        .bind_connected_stream_for_test(&server, move |_| {
            sequence.lock().unwrap().pop_front().unwrap()
        })
        .unwrap();
    let dispatcher = Dispatcher::with_defaults();
    let handle = std::thread::spawn(move || {
        let mut limiter = RateLimiter::rc9_default();
        let clock = || 0u64;
        serve_bound_connection(
            &mut server,
            &proof,
            &dispatcher,
            &context,
            &mut limiter,
            &clock,
        )
    });
    let payload = br#"{"id":1,"method":"bitty.debug/getSnapshot","version":"1.0"}"#;
    // CTX-0784: the server rejects the recheck before it reads a single
    // request byte, so this write races the fail-closed shutdown it is
    // testing. The raced write is itself a close observation, not a defect:
    // `EPIPE`/`ECONNRESET` on a refused stream proves the bound connection
    // went away. Any other error still fails, and a request that did reach
    // the wire is still parsed and checked for the `Unauthenticated` body.
    let request = match client.write_all(&encode_frame(payload).unwrap()) {
        Ok(()) => Some(()),
        Err(err) => {
            assert!(
                matches!(
                    err.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ),
                "unexpected request write error: {err:?}"
            );
            None
        }
    };
    let mut header = [0u8; 4];
    match request.map(|()| client.read_exact(&mut header)) {
        Some(Ok(())) => {
            let len = u32::from_be_bytes(header) as usize;
            let mut response = vec![0u8; len];
            client.read_exact(&mut response).unwrap();
            assert!(
                String::from_utf8(response)
                    .unwrap()
                    .contains("Unauthenticated")
            );
        }
        Some(Err(err)) => {
            // The recheck refusal closes the bound socket before any response.
            // Linux/other Unix surface that close while request bytes are
            // still unread as ECONNRESET; macOS ARM64 can complete an orderly
            // close, so the client observes EOF (`UnexpectedEof`) instead.
            // Both are fail-closed closes — pin the exact kind off macOS and
            // widen on it so the divergence stays contained.
            #[cfg(target_os = "macos")]
            assert!(
                matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
                ),
                "unexpected close error kind: {err:?}"
            );
            #[cfg(not(target_os = "macos"))]
            assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        }
        // The request write already observed the refusal close; the read side
        // of that same close is asserted by the read at the end of the test.
        None => {}
    }
    assert!(matches!(
        handle.join().unwrap(),
        Err(IpcError::Unauthenticated { .. })
    ));
    let mut byte = [0u8; 1];
    assert!(matches!(client.read(&mut byte), Ok(0) | Err(_)));
}

#[cfg(unix)]
#[test]
fn every_privileged_dispatch_rechecks_the_bound_peer() {
    use std::collections::VecDeque;
    use std::os::unix::net::UnixStream;

    let peer = crate::auth::verify_peer_for_connection(
        crate::auth::PeerCredentials::new(1000, 1000, 1),
        1000,
    )
    .unwrap();
    let (_client, server) = UnixStream::pair().unwrap();
    let sequence = Arc::new(Mutex::new(VecDeque::from([
        Ok(peer),
        Ok(peer),
        Err(IpcError::Unauthenticated {
            reason: "synthetic recheck mismatch".into(),
        }),
    ])));
    let mut granted = crate::scope::ScopeSet::new();
    granted.insert(crate::scope::Scope::DebugInspect);
    // The debug read surfaces intersect a debug scope with `terminal.inspect`
    // (CTX-0792 #1404); grant both explicitly so the capability gate passes
    // and this test keeps testing the per-dispatch recheck it is named for.
    granted.insert(crate::scope::Scope::TerminalInspect);
    let mut context =
        ServeContext::with_granted_session_for_tests(&test_server_info(), granted, "recheck-probe");
    context
        .bind_connected_stream_for_test(&server, move |_| {
            sequence.lock().unwrap().pop_front().unwrap()
        })
        .unwrap();
    let request = DevtoolsRequest {
        id_raw: "1".into(),
        method: "bitty.debug/getSnapshot".into(),
        has_jsonrpc: false,
        params_raw: None,
    };
    let dispatcher = Dispatcher::with_defaults();
    assert!(dispatcher.dispatch(&context, &request).is_ok());
    let err = dispatcher.dispatch(&context, &request).unwrap_err();
    assert_eq!(err.code, "Unauthenticated");
}

#[cfg(unix)]
#[test]
fn pathname_attestation_cannot_mint_a_connected_peer() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};

    let base = std::env::temp_dir().join(format!("bitty-ctx0768-{}-pathname", std::process::id()));
    let socket_path = base.join("bitty/a.sock");
    let socket_string = socket_path.to_str().unwrap().to_string();
    let _dir = prepare_socket_dir(&socket_string).unwrap();
    let listener = UnixListener::bind(&socket_string).unwrap();
    std::fs::set_permissions(&socket_string, std::fs::Permissions::from_mode(0o600)).unwrap();
    let runtime_uid = std::fs::symlink_metadata(&socket_string).unwrap().uid();
    assert!(verify_socket_endpoint_for_connect(&socket_string, runtime_uid).is_ok());
    let legacy_marker = transport_attested_peer(&socket_string, runtime_uid).unwrap();
    assert_eq!(legacy_marker.peer_uid(), runtime_uid);
    let mut context = ServeContext::new(&test_server_info());
    assert!(context.recheck_before_dispatch().is_err());
    let client = UnixStream::connect(&socket_string).unwrap();
    let (server, _) = listener.accept().unwrap();
    let result: Result<ConnectedPeerProof, IpcError> =
        context.bind_connected_stream_for_test(&server, |_| {
            Err(IpcError::Unauthenticated {
                reason: "synthetic connected peer mismatch".into(),
            })
        });
    assert!(matches!(result, Err(IpcError::Unauthenticated { .. })));
    drop(client);
    drop(server);
    drop(listener);
    let _ = std::fs::remove_dir_all(&base);
}

#[cfg(unix)]
#[test]
fn serve_connection_rate_limits_with_error_response() {
    use std::os::unix::net::UnixStream;

    let (mut client, mut server) = UnixStream::pair().unwrap();
    let dispatcher = Dispatcher::with_defaults();
    let context = test_context();
    let peer = crate::auth::verify_peer_for_connection(
        crate::auth::PeerCredentials::new(1000, 1000, 1),
        1000,
    )
    .unwrap();
    let mut limiter = RateLimiter::new(100, 1);
    let clock = || 0u64;

    let handle = std::thread::spawn(move || {
        serve_connection(
            &mut server,
            peer,
            &dispatcher,
            &context,
            &mut limiter,
            &clock,
        )
    });

    for id in 1..=2u64 {
        let payload =
            format!("{{\"id\":{id},\"method\":\"bitty.debug/ping\",\"version\":\"1.0\"}}");
        let wire = encode_frame(payload.as_bytes()).unwrap();
        client.write_all(&wire).unwrap();
    }
    let mut texts = Vec::new();
    for _ in 0..2 {
        let mut header = [0u8; 4];
        client.read_exact(&mut header).unwrap();
        let len = u32::from_be_bytes(header) as usize;
        let mut body = vec![0u8; len];
        client.read_exact(&mut body).unwrap();
        texts.push(String::from_utf8(body).unwrap());
    }
    assert!(texts[0].contains("\"ok\":true"));
    assert!(texts[1].contains("RateLimited"));
    drop(client);
    let stats = handle.join().unwrap().unwrap();
    assert_eq!(stats.requests, 2);
    assert_eq!(stats.denied, 1);
}

#[cfg(unix)]
#[test]
fn endpoint_rate_budget_is_shared_across_connections() {
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    let limiter = Arc::new(Mutex::new(RateLimiter::new(100, 1)));
    for expected_denied in [false, true] {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let dispatcher = Dispatcher::with_defaults();
        let context = test_context();
        let peer = crate::auth::verify_peer_for_connection(
            crate::auth::PeerCredentials::new(1000, 1000, 1),
            1000,
        )
        .unwrap();
        let limiter = Arc::clone(&limiter);
        let handle = std::thread::spawn(move || {
            let clock = || 0u64;
            dispatcher.serve_connection_with_shared_limiter(
                &mut server,
                peer,
                &context,
                &limiter,
                &clock,
            )
        });
        client
            .write_all(
                &encode_frame(br#"{"id":1,"method":"bitty.debug/ping","version":"1.0"}"#).unwrap(),
            )
            .unwrap();
        let mut header = [0u8; 4];
        client.read_exact(&mut header).unwrap();
        let len = u32::from_be_bytes(header) as usize;
        let mut body = vec![0u8; len];
        client.read_exact(&mut body).unwrap();
        let text = String::from_utf8(body).unwrap();
        assert_eq!(text.contains("RateLimited"), expected_denied);
        drop(client);
        handle.join().unwrap().unwrap();
    }
}

/// CTX-0792 / #1404: one conforming client gets the full accepted RC-9 burst
/// (no hidden per-connection share), and the budget it spends is the endpoint
/// budget every other connection draws from.
#[cfg(unix)]
#[test]
fn single_connection_gets_the_full_rc9_burst_from_the_shared_endpoint_budget() {
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    let endpoint = Arc::new(Mutex::new(RateLimiter::rc9_default()));
    let burst = crate::limits::RC9_BURST_PER_SEC as usize;

    let drive = |requests: usize| -> usize {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let dispatcher = Dispatcher::with_defaults();
        let context = test_context();
        let peer = crate::auth::verify_peer_for_connection(
            crate::auth::PeerCredentials::new(1000, 1000, 1),
            1000,
        )
        .unwrap();
        let endpoint = Arc::clone(&endpoint);
        let handle = std::thread::spawn(move || {
            let clock = || 0u64;
            dispatcher.serve_connection_with_shared_limiter(
                &mut server,
                peer,
                &context,
                &endpoint,
                &clock,
            )
        });
        let mut denied = 0usize;
        for id in 1..=requests as u64 {
            let payload =
                format!("{{\"id\":{id},\"method\":\"bitty.debug/ping\",\"version\":\"1.0\"}}");
            if client
                .write_all(&encode_frame(payload.as_bytes()).unwrap())
                .is_err()
            {
                break;
            }
            let mut header = [0u8; 4];
            if client.read_exact(&mut header).is_err() {
                break;
            }
            let len = u32::from_be_bytes(header) as usize;
            let mut body = vec![0u8; len];
            if client.read_exact(&mut body).is_err() {
                break;
            }
            if String::from_utf8(body).unwrap().contains("RateLimited") {
                denied += 1;
            }
        }
        drop(client);
        let _ = handle.join().unwrap().unwrap();
        denied
    };

    // The whole documented burst is admitted for a single client...
    assert_eq!(drive(burst), 0, "a single client gets the full RC-9 burst");
    // ...and it was the shared endpoint budget: a second connection in the same
    // instant is shed instead of receiving a fresh budget.
    assert_eq!(
        drive(1),
        1,
        "a new connection does not reset the endpoint budget"
    );
}

/// CTX-0792: a panic in any connection thread must not deny IPC traffic for the
/// process lifetime. The endpoint limiter is recovered with `into_inner`, the
/// pattern every other shared lock in this crate uses.
#[cfg(unix)]
#[test]
fn endpoint_rate_budget_recovers_from_a_poisoned_lock() {
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    let endpoint = Arc::new(Mutex::new(RateLimiter::new(100, 2)));
    let poisoner = Arc::clone(&endpoint);
    let _ = std::thread::spawn(move || {
        let _guard = poisoner.lock().expect("first acquisition wins");
        panic!("simulated panic while holding the endpoint budget");
    })
    .join();
    assert!(endpoint.is_poisoned(), "fixture must poison the limiter");

    let (mut client, mut server) = UnixStream::pair().unwrap();
    let dispatcher = Dispatcher::with_defaults();
    let context = test_context();
    let peer = crate::auth::verify_peer_for_connection(
        crate::auth::PeerCredentials::new(1000, 1000, 1),
        1000,
    )
    .unwrap();
    let handle = std::thread::spawn(move || {
        let clock = || 0u64;
        dispatcher.serve_connection_with_shared_limiter(
            &mut server,
            peer,
            &context,
            &endpoint,
            &clock,
        )
    });
    client
        .write_all(
            &encode_frame(br#"{"id":1,"method":"bitty.debug/ping","version":"1.0"}"#).unwrap(),
        )
        .unwrap();
    let mut header = [0u8; 4];
    client.read_exact(&mut header).unwrap();
    let len = u32::from_be_bytes(header) as usize;
    let mut body = vec![0u8; len];
    client.read_exact(&mut body).unwrap();
    let text = String::from_utf8(body).unwrap();
    assert!(
        text.contains("\"ok\":true"),
        "a poisoned budget must be recovered, not reported as unavailable: {text}"
    );
    drop(client);
    let stats = handle.join().unwrap().unwrap();
    assert_eq!(stats.denied, 0);
}

#[cfg(unix)]
#[test]
fn serve_connection_oversize_frame_closes() {
    use std::os::unix::net::UnixStream;

    let (mut client, mut server) = UnixStream::pair().unwrap();
    server
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let dispatcher = Dispatcher::with_defaults();
    let context = test_context();
    let peer = crate::auth::verify_peer_for_connection(
        crate::auth::PeerCredentials::new(1000, 1000, 1),
        1000,
    )
    .unwrap();
    let mut limiter = RateLimiter::rc9_default();
    let clock = || 0u64;

    let handle = std::thread::spawn(move || {
        serve_connection(
            &mut server,
            peer,
            &dispatcher,
            &context,
            &mut limiter,
            &clock,
        )
    });

    let huge = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes();
    client.write_all(&huge).unwrap();
    let mut header = [0u8; 4];
    client.read_exact(&mut header).unwrap();
    let len = u32::from_be_bytes(header) as usize;
    let mut body = vec![0u8; len];
    client.read_exact(&mut body).unwrap();
    let text = String::from_utf8(body).unwrap();
    assert!(text.contains("FrameTooLarge"));
    let stats = handle.join().unwrap().unwrap();
    assert_eq!(stats.framing_errors, 1);
}

// ── inbound request continuation (Amendment A4, #1482) ──────────────

/// Method the continuation fixtures dispatch to; records every call's params.
#[cfg(unix)]
const CONTINUATION_PROBE: &str = "bitty.debug/continuationProbe";

#[cfg(unix)]
fn continuation_probe_calls() -> &'static Mutex<Vec<String>> {
    static CALLS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    CALLS.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(unix)]
fn continuation_probe(
    _context: &ServeContext,
    request: &DevtoolsRequest,
) -> Result<String, HandlerError> {
    continuation_probe_calls()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(request.params_raw.clone().unwrap_or_default());
    Ok("{\"probed\":true}".to_string())
}

/// Dispatches recorded for `tag` (fixtures run in parallel, so each one
/// filters by its own tag).
#[cfg(unix)]
fn continuation_probe_count(tag: &str) -> usize {
    continuation_probe_calls()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|params| params.contains(tag))
        .count()
}

/// A probe envelope for `tag` padded with insignificant whitespace to `len`.
#[cfg(unix)]
fn padded_probe_request(id: u32, tag: &str, len: usize) -> Vec<u8> {
    let head = format!(
        "{{\"id\":{id},\"method\":\"{CONTINUATION_PROBE}\",\"version\":\"1.0\",\"params\":{{\"tag\":\"{tag}\"}}"
    );
    let mut request = head.into_bytes();
    request.resize(len - 1, b' ');
    request.push(b'}');
    request
}

/// Serve one hermetic connection in a thread with the probe registered.
#[cfg(unix)]
fn spawn_continuation_server(
    read_timeout: std::time::Duration,
    clock: impl Fn() -> u64 + Send + 'static,
) -> (
    std::os::unix::net::UnixStream,
    std::thread::JoinHandle<Result<ConnectionStats, IpcError>>,
) {
    use std::os::unix::net::UnixStream;

    let (client, mut server) = UnixStream::pair().unwrap();
    server.set_read_timeout(Some(read_timeout)).unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut dispatcher = Dispatcher::with_defaults();
    dispatcher
        .register(CONTINUATION_PROBE, continuation_probe)
        .unwrap();
    let context = test_context();
    let peer = crate::auth::verify_peer_for_connection(
        crate::auth::PeerCredentials::new(1000, 1000, 1),
        1000,
    )
    .unwrap();
    let handle = std::thread::spawn(move || {
        let mut limiter = RateLimiter::rc9_default();
        serve_connection(
            &mut server,
            peer,
            &dispatcher,
            &context,
            &mut limiter,
            &clock,
        )
    });
    (client, handle)
}

/// Read one response frame, or `None` when the server closed the stream.
#[cfg(unix)]
fn read_response(client: &mut std::os::unix::net::UnixStream) -> Option<String> {
    let mut header = [0u8; 4];
    client.read_exact(&mut header).ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(header) as usize];
    client.read_exact(&mut body).unwrap();
    Some(String::from_utf8(body).unwrap())
}

#[cfg(unix)]
fn write_frames(client: &mut std::os::unix::net::UnixStream, frames: &[Vec<u8>]) {
    for frame in frames {
        client.write_all(frame).unwrap();
    }
}

#[cfg(unix)]
fn assert_one_exchange(len: usize, tag: &str) {
    let (mut client, handle) = spawn_continuation_server(std::time::Duration::from_secs(5), || 0);
    let request = padded_probe_request(41, tag, len);
    let frames = encode_request_frames(&request, 9).unwrap();
    assert!(frames.len() > 1, "fixture must need continuation");
    write_frames(&mut client, &frames);
    let text = read_response(&mut client).expect("one response");
    assert!(text.contains("\"id\":41"), "{text}");
    assert!(text.contains("\"probed\":true"), "{text}");
    drop(client);
    let stats = handle.join().unwrap().unwrap();
    assert_eq!(
        stats.requests, 1,
        "one logical request, not one per fragment"
    );
    assert_eq!(stats.responses, 1);
    assert_eq!(stats.framing_errors, 0);
    assert_eq!(continuation_probe_count(tag), 1);
}

#[cfg(unix)]
#[test]
fn continuation_just_above_one_frame_is_one_exchange() {
    assert_one_exchange(MAX_FRAME_BYTES + 1, "a4-above-one-frame");
}

#[cfg(unix)]
#[test]
fn continuation_near_the_inbound_limit_is_one_exchange() {
    assert_one_exchange(MAX_LOGICAL_REQUEST_BYTES - 1, "a4-near-limit");
}

#[cfg(unix)]
#[test]
fn continuation_keeps_method_params_caps_and_correlates_the_error() {
    let tag = "a4-params-cap";
    let (mut client, handle) = spawn_continuation_server(std::time::Duration::from_secs(5), || 0);
    let blob = "x".repeat(MAX_FRAME_BYTES);
    let request = format!(
        "{{\"id\":42,\"method\":\"{CONTINUATION_PROBE}\",\"version\":\"1.0\",\"params\":{{\"tag\":\"{tag}\",\"blob\":\"{blob}\"}}}}"
    );
    write_frames(
        &mut client,
        &encode_request_frames(request.as_bytes(), 3).unwrap(),
    );
    let text = read_response(&mut client).expect("one response");
    assert!(text.contains("\"id\":42"), "{text}");
    assert!(text.contains("PayloadTooLarge"), "{text}");
    drop(client);
    let stats = handle.join().unwrap().unwrap();
    assert_eq!(stats.requests, 1);
    assert_eq!(continuation_probe_count(tag), 0);
}

/// Send `frames`, expect one `id` 0 error carrying `code`, then EOF, with no
/// dispatch of `tag`.
#[cfg(unix)]
fn assert_fails_closed(
    clock: impl Fn() -> u64 + Send + 'static,
    frames: &[Vec<u8>],
    tag: &str,
    code: &str,
) {
    let (mut client, handle) = spawn_continuation_server(std::time::Duration::from_secs(5), clock);
    // The server may close before the last frame is written (it fails closed
    // at the first violation), so a broken pipe here is expected.
    for frame in frames {
        if client.write_all(frame).is_err() {
            break;
        }
    }
    let text = read_response(&mut client).expect("one error response");
    assert!(text.contains(code), "{text}");
    assert!(text.contains("\"id\":0"), "{text}");
    assert!(
        read_response(&mut client).is_none(),
        "connection must close"
    );
    let stats = handle.join().unwrap().unwrap();
    assert_eq!(stats.requests, 0, "nothing was admitted");
    assert_eq!(stats.framing_errors, 1);
    assert_eq!(continuation_probe_count(tag), 0, "nothing was dispatched");
}

#[cfg(unix)]
#[test]
fn continuation_interleaved_plain_frame_fails_closed() {
    let tag = "a4-interleaved";
    let request = padded_probe_request(43, tag, MAX_FRAME_BYTES + 100);
    let mut frames = encode_request_frames(&request, 5).unwrap();
    frames.truncate(1);
    let plain = format!(
        "{{\"id\":44,\"method\":\"{CONTINUATION_PROBE}\",\"version\":\"1.0\",\"params\":{{\"tag\":\"{tag}\"}}}}"
    );
    frames.push(encode_frame(plain.as_bytes()).unwrap());
    assert_fails_closed(|| 0, &frames, tag, "ContinuationInvalid");
}

#[cfg(unix)]
#[test]
fn continuation_out_of_order_fragment_fails_closed() {
    let tag = "a4-out-of-order";
    let request = padded_probe_request(45, tag, CONTINUATION_CHUNK_BYTES * 2 + 10);
    let mut frames = encode_request_frames(&request, 6).unwrap();
    assert_eq!(frames.len(), 3);
    frames.swap(1, 2);
    assert_fails_closed(|| 0, &frames, tag, "ContinuationInvalid");
}

#[cfg(unix)]
#[test]
fn continuation_over_limit_total_fails_closed() {
    let tag = "a4-over-limit";
    let mut first = encode_request_frames(&padded_probe_request(46, tag, MAX_FRAME_BYTES + 1), 8)
        .unwrap()
        .remove(0);
    // Rewrite the declared total (payload offset 12, after the 4-byte prefix).
    let over = u32::try_from(MAX_LOGICAL_REQUEST_BYTES + 1).unwrap();
    first[4 + 12..4 + 16].copy_from_slice(&over.to_be_bytes());
    assert_fails_closed(|| 0, &[first], tag, "FrameTooLarge");
}

#[cfg(unix)]
#[test]
fn continuation_late_final_fragment_fails_closed() {
    let tag = "a4-late";
    let request = padded_probe_request(47, tag, MAX_FRAME_BYTES + 1);
    let frames = encode_request_frames(&request, 10).unwrap();
    // The first fragment is read at t=0; every later clock read is past the
    // deadline.
    let calls = std::sync::atomic::AtomicU64::new(0);
    let clock = move || {
        if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            0
        } else {
            CONTINUATION_DEADLINE_MS + 1
        }
    };
    assert_fails_closed(clock, &frames, tag, "ContinuationTimeout");
}

#[cfg(unix)]
#[test]
fn continuation_stalled_stream_reports_timeout_without_dispatch() {
    let tag = "a4-stalled";
    let (mut client, handle) =
        spawn_continuation_server(std::time::Duration::from_millis(200), || 0);
    let request = padded_probe_request(48, tag, MAX_FRAME_BYTES + 1);
    let frames = encode_request_frames(&request, 11).unwrap();
    write_frames(&mut client, &frames[..1]);
    let text = read_response(&mut client).expect("one timeout response");
    assert!(text.contains("ContinuationTimeout"), "{text}");
    assert!(text.contains("\"id\":0"), "{text}");
    let stats = handle.join().unwrap().unwrap();
    assert_eq!(stats.requests, 0);
    assert_eq!(stats.framing_errors, 1);
    assert_eq!(continuation_probe_count(tag), 0);
}

#[cfg(unix)]
#[test]
fn continuation_slow_drip_is_cut_at_the_deadline() {
    // CodeRabbit on #1525: while a reassembly is open, every read is bounded
    // by the time left before the continuation deadline, so dripping a
    // fragment byte by byte cannot hold the connection past it. The fake
    // clock advances 2 s per reading, so the deadline passes after a few
    // drips; the 30 s idle timeout alone would keep the connection open far
    // longer than the client waits.
    let tag = "a4-slow-drip";
    let ticks = std::sync::atomic::AtomicU64::new(0);
    let clock = move || ticks.fetch_add(2_000, std::sync::atomic::Ordering::SeqCst);
    let (mut client, handle) = spawn_continuation_server(std::time::Duration::from_secs(30), clock);
    let request = padded_probe_request(50, tag, CONTINUATION_CHUNK_BYTES * 2 + 10);
    let frames = encode_request_frames(&request, 13).unwrap();
    assert_eq!(
        frames[1].len(),
        4 + MAX_FRAME_BYTES,
        "the dripped fragment is full"
    );
    client.write_all(&frames[0]).unwrap();
    // Only the first bytes of the full second fragment ever arrive.
    for byte in frames[1].iter().take(64) {
        if client.write_all(&[*byte]).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let text = read_response(&mut client).expect("the deadline must cut the drip");
    assert!(text.contains("ContinuationTimeout"), "{text}");
    assert!(text.contains("\"id\":0"), "{text}");
    let stats = handle.join().unwrap().unwrap();
    assert_eq!(stats.requests, 0);
    assert_eq!(stats.framing_errors, 1);
    assert_eq!(continuation_probe_count(tag), 0);
}

#[cfg(unix)]
#[test]
fn continuation_eof_mid_request_closes_silently() {
    let tag = "a4-eof";
    let (mut client, handle) = spawn_continuation_server(std::time::Duration::from_secs(5), || 0);
    let request = padded_probe_request(49, tag, CONTINUATION_CHUNK_BYTES * 2 + 1);
    let frames = encode_request_frames(&request, 12).unwrap();
    write_frames(&mut client, &frames[..2]);
    client.shutdown(std::net::Shutdown::Write).unwrap();
    assert!(read_response(&mut client).is_none(), "no reply after EOF");
    let stats = handle.join().unwrap().unwrap();
    assert_eq!(stats.requests, 0);
    assert_eq!(stats.responses, 0);
    assert_eq!(continuation_probe_count(tag), 0);
}

// ── directory attestation (unix, temp dirs) ─────────────────────────

#[cfg(unix)]
#[test]
fn prepare_socket_dir_enforces_0700() {
    let base = std::env::temp_dir().join(format!(
        "bitty-ctx0144-{}-{}",
        std::process::id(),
        "prepare"
    ));
    let socket_path = base.join("bitty/t.sock");
    let socket_str = socket_path.to_str().unwrap();
    let attestation = prepare_socket_dir(socket_str).unwrap();
    assert_eq!(attestation.dir_mode, DIR_MODE);
    // Second call on the existing good leaf succeeds.
    let again = prepare_socket_dir(socket_str).unwrap();
    assert_eq!(again, attestation);
    std::fs::remove_dir_all(&base).ok();
}

#[cfg(unix)]
#[test]
fn prepare_socket_dir_rejects_bad_mode() {
    use std::os::unix::fs::PermissionsExt;

    let base = std::env::temp_dir().join(format!(
        "bitty-ctx0144-{}-{}",
        std::process::id(),
        "badmode"
    ));
    let leaf = base.join("bitty");
    std::fs::create_dir_all(&leaf).unwrap();
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();
    let socket_str = leaf.join("t.sock").to_str().unwrap().to_string();
    let err = prepare_socket_dir(&socket_str).unwrap_err();
    assert!(matches!(err, IpcError::Unauthenticated { .. }));
    std::fs::remove_dir_all(&base).ok();
}

/// CR-IPC-01: a symlinked socket directory must fail closed even when the
/// link target is a well-formed `0700` directory owned by us.
#[cfg(unix)]
#[test]
fn prepare_socket_dir_rejects_symlinked_leaf() {
    use std::os::unix::fs::PermissionsExt;

    let base = std::env::temp_dir().join(format!(
        "bitty-ctx0203-{}-{}",
        std::process::id(),
        "symlink-leaf"
    ));
    let target = base.join("real");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = base.join("bitty");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let socket_str = link.join("t.sock").to_str().unwrap().to_string();
    let err = prepare_socket_dir(&socket_str).unwrap_err();
    assert!(
        matches!(err, IpcError::Unauthenticated { .. }),
        "symlinked leaf must fail closed, got: {err:?}"
    );
    std::fs::remove_dir_all(&base).ok();
}

/// CR-IPC-01: a symlinked socket path must fail closed before any chmod
/// is applied to its target.
#[cfg(unix)]
#[test]
fn attest_bound_socket_rejects_symlink() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let base = std::env::temp_dir().join(format!(
        "bitty-ctx0203-{}-{}",
        std::process::id(),
        "symlink-sock"
    ));
    let dir_path = base.join("bitty");
    std::fs::create_dir_all(&dir_path).unwrap();
    std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket_str = dir_path.join("t.sock").to_str().unwrap().to_string();
    let attestation = prepare_socket_dir(&socket_str).unwrap();

    let real = dir_path.join("real.sock");
    std::fs::write(&real, b"x").unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644)).unwrap();
    let link_path = dir_path.join("link.sock");
    std::os::unix::fs::symlink(&real, &link_path).unwrap();
    let link_str = link_path.to_str().unwrap();

    let err = attest_bound_socket(link_str, &attestation).unwrap_err();
    assert!(
        matches!(err, IpcError::Unauthenticated { .. }),
        "symlinked socket must fail closed, got: {err:?}"
    );
    // Fail-closed before chmod: the link target keeps its pre-existing mode.
    let target_mode = std::fs::metadata(&real).unwrap().mode() & 0o777;
    assert_eq!(target_mode, 0o644);
    std::fs::remove_dir_all(&base).ok();
}

/// CTX-0463 (issue 744): the accept boundary must verify the endpoint
/// instead of attesting the UID verbatim. Happy path mints a marker;
/// tampered endpoints and UID mismatches fail closed.
#[cfg(unix)]
#[test]
fn transport_attested_peer_verifies_endpoint() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let base = std::env::temp_dir().join(format!("bitty-ctx0463-{}-attested", std::process::id()));
    let socket_path = base.join("bitty/a.sock");
    let socket_str = socket_path.to_str().unwrap().to_string();
    let _dir = prepare_socket_dir(&socket_str).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(&socket_str).unwrap();
    std::fs::set_permissions(&socket_str, std::fs::Permissions::from_mode(0o600)).unwrap();
    let euid = std::fs::symlink_metadata(&socket_str).unwrap().uid();

    // Happy path: owned 0700/0600 endpoint mints a marker.
    assert!(transport_attested_peer(&socket_str, euid).is_ok());

    // Hostile: wrong runtime UID fails closed (no marker minted).
    let foreign = euid.wrapping_add(1);
    let err = transport_attested_peer(&socket_str, foreign).unwrap_err();
    assert!(
        matches!(err, IpcError::Unauthenticated { .. }),
        "foreign UID must fail closed, got: {err:?}"
    );

    // Hostile: loosened socket mode fails closed.
    std::fs::set_permissions(&socket_str, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = transport_attested_peer(&socket_str, euid).unwrap_err();
    assert!(
        matches!(err, IpcError::Unauthenticated { .. }),
        "0644 socket must fail closed, got: {err:?}"
    );
    std::fs::set_permissions(&socket_str, std::fs::Permissions::from_mode(0o600)).unwrap();

    // Hostile: loosened directory mode fails closed.
    let leaf = base.join("bitty");
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();
    let err = transport_attested_peer(&socket_str, euid).unwrap_err();
    assert!(
        matches!(err, IpcError::Unauthenticated { .. }),
        "0755 dir must fail closed, got: {err:?}"
    );
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o700)).unwrap();

    drop(listener);
    std::fs::remove_dir_all(&base).ok();
}

/// CTX-0463 (issue 744): symlinked endpoints fail closed at the accept
/// boundary, even when the link target is well-formed.
#[cfg(unix)]
#[test]
fn transport_attested_peer_rejects_symlinked_endpoint() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let base = std::env::temp_dir().join(format!(
        "bitty-ctx0463-{}-attested-link",
        std::process::id()
    ));
    let dir_path = base.join("bitty");
    std::fs::create_dir_all(&dir_path).unwrap();
    std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let real = dir_path.join("real.sock");
    let listener = std::os::unix::net::UnixListener::bind(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
    let euid = std::fs::symlink_metadata(&real).unwrap().uid();

    let link = dir_path.join("link.sock");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let err = transport_attested_peer(link.to_str().unwrap(), euid).unwrap_err();
    assert!(
        matches!(err, IpcError::Unauthenticated { .. }),
        "symlinked socket must fail closed, got: {err:?}"
    );
    drop(listener);
    std::fs::remove_dir_all(&base).ok();
}

/// CTX-0528 (IPC-001): a foreign-owned endpoint fails closed before any
/// request byte is read — the attestation path cannot be satisfied by
/// endpoint ownership alone.
///
/// Hostile: a socket directory owned by another UID (simulated by asking
/// for attestation under a different `runtime_uid`) mints no marker, even
/// though the 0700/0600 shape is well-formed.
#[cfg(unix)]
#[test]
fn ipc001_foreign_uid_endpoint_rejected_before_first_byte() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let base =
        std::env::temp_dir().join(format!("bitty-ctx0528-{}-foreign-uid", std::process::id()));
    let socket_path = base.join("bitty/a.sock");
    let socket_str = socket_path.to_str().unwrap().to_string();
    let _dir = prepare_socket_dir(&socket_str).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(&socket_str).unwrap();
    std::fs::set_permissions(&socket_str, std::fs::Permissions::from_mode(0o600)).unwrap();
    let euid = std::fs::symlink_metadata(&socket_str).unwrap().uid();
    let foreign = euid.wrapping_add(1);

    // Marker minting fails closed for the foreign UID: no credential bytes
    // are read (there is no stream here at all), and no marker exists to
    // serve with.
    let err = transport_attested_peer(&socket_str, foreign).unwrap_err();
    assert!(
        matches!(err, IpcError::Unauthenticated { .. }),
        "foreign-uid endpoint must fail closed, got: {err:?}"
    );

    drop(listener);
    std::fs::remove_dir_all(&base).ok();
}

/// CTX-0528 (IPC-001): a symlinked endpoint fails closed at the accept
/// boundary — no marker is minted for a link, even when its target is a
/// well-formed 0700/0600 endpoint owned by us.
#[cfg(unix)]
#[test]
fn ipc001_symlink_endpoint_rejected_before_first_byte() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let base = std::env::temp_dir().join(format!("bitty-ctx0528-{}-symlink", std::process::id()));
    let dir_path = base.join("bitty");
    std::fs::create_dir_all(&dir_path).unwrap();
    std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let real = dir_path.join("real.sock");
    let listener = std::os::unix::net::UnixListener::bind(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
    let euid = std::fs::symlink_metadata(&real).unwrap().uid();

    let link = dir_path.join("link.sock");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let err = transport_attested_peer(link.to_str().unwrap(), euid).unwrap_err();
    assert!(
        matches!(err, IpcError::Unauthenticated { .. }),
        "symlinked endpoint must fail closed, got: {err:?}"
    );
    drop(listener);
    std::fs::remove_dir_all(&base).ok();
}

/// CTX-0528 (IPC-001): a world-writable directory fails closed at the
/// accept boundary — group/other permission bits on the leaf directory
/// reject attestation even for the owning UID.
#[cfg(unix)]
#[test]
fn ipc001_world_writable_dir_rejected_before_first_byte() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let base = std::env::temp_dir().join(format!("bitty-ctx0528-{}-wwdir", std::process::id()));
    let socket_path = base.join("bitty/a.sock");
    let socket_str = socket_path.to_str().unwrap().to_string();
    let _dir = prepare_socket_dir(&socket_str).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(&socket_str).unwrap();
    std::fs::set_permissions(&socket_str, std::fs::Permissions::from_mode(0o600)).unwrap();
    let euid = std::fs::symlink_metadata(&socket_str).unwrap().uid();

    // Hostile: another local user made the leaf world-writable (0777).
    let leaf = base.join("bitty");
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = transport_attested_peer(&socket_str, euid).unwrap_err();
    assert!(
        matches!(err, IpcError::Unauthenticated { .. }),
        "world-writable dir must fail closed, got: {err:?}"
    );

    drop(listener);
    std::fs::remove_dir_all(&base).ok();
}

/// CTX-0528 (IPC-001): no constructor path mints a `VerifiedPeer` marker
/// without passing the verified endpoint — the marker is unsatisfiable by
/// endpoint ownership alone. Both failure classes below are fail-closed
/// (`Unauthenticated`) and carry token-free reasons.
#[cfg(unix)]
#[test]
fn ipc001_marker_not_constructible_without_verified_endpoint() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let base = std::env::temp_dir().join(format!("bitty-ctx0528-{}-no-marker", std::process::id()));
    let socket_path = base.join("bitty/a.sock");
    let socket_str = socket_path.to_str().unwrap().to_string();
    let _dir = prepare_socket_dir(&socket_str).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(&socket_str).unwrap();
    std::fs::set_permissions(&socket_str, std::fs::Permissions::from_mode(0o600)).unwrap();
    let euid = std::fs::symlink_metadata(&socket_str).unwrap().uid();

    // Missing socket file: nothing to attest, fail closed as Unavailable.
    let missing = base.join("bitty/missing.sock");
    let err = transport_attested_peer(missing.to_str().unwrap(), euid).unwrap_err();
    assert!(
        matches!(
            err,
            IpcError::Unavailable { .. } | IpcError::Unauthenticated { .. }
        ),
        "missing endpoint must fail closed, got: {err:?}"
    );

    // Foreign UID against a well-formed endpoint: fail closed as
    // Unauthenticated with a peer-mismatch reason (token-free: no fd or
    // credential bytes echoed).
    let foreign = euid.wrapping_add(1);
    let err = transport_attested_peer(&socket_str, foreign).unwrap_err();
    let reason = match err {
        IpcError::Unauthenticated { reason } => reason,
        other => panic!("expected Unauthenticated, got {other:?}"),
    };
    assert!(
        !reason.contains(&socket_str),
        "failure reason must not echo the socket path bytes: {reason}"
    );

    drop(listener);
    std::fs::remove_dir_all(&base).ok();
}

/// CTX-0463 (issue 744): `resolve_socket_path` is pure advisory resolution;
/// a non-empty `BITTY_SOCKET` is returned verbatim after shape checks, so
/// the connect boundary must verify ownership before use.
#[cfg(unix)]
#[test]
fn bitty_socket_verbatim_path_still_requires_verification() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // Pure resolution returns the advisory path with no endpoint checks.
    let path =
        resolve_socket_path(1000, Some("/run/user/1000"), Some("/tmp/custom.sock"), None).unwrap();
    assert_eq!(path, "/tmp/custom.sock");

    // The same path fails verification when the endpoint is absent or
    // tampered: missing socket is Unavailable (fail-closed, never connect).
    let missing = verify_socket_endpoint_for_connect(&path, 1000);
    assert!(
        matches!(
            missing,
            Err(IpcError::Unavailable { .. }) | Err(IpcError::Unauthenticated { .. })
        ),
        "unverifiable BITTY_SOCKET path must fail closed, got: {missing:?}"
    );

    // Tampered live endpoint: 0644 socket fails verification.
    let base =
        std::env::temp_dir().join(format!("bitty-ctx0463-{}-bitty-socket", std::process::id()));
    let socket_path = base.join("bitty/b.sock");
    let socket_str = socket_path.to_str().unwrap().to_string();
    let _dir = prepare_socket_dir(&socket_str).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(&socket_str).unwrap();
    // Deliberately leave the servo chmod undone: raw bind mode is not 0600.
    let euid = {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(&socket_str).unwrap().uid()
    };
    let _ = euid;
    let resolved = resolve_socket_path(euid, None, Some(&socket_str), None).unwrap();
    assert_eq!(resolved, socket_str);
    // Raw bind mode (umask-derived) must not verify without the 0600 chmod.
    let raw_mode = std::fs::symlink_metadata(&socket_str).unwrap().mode() & 0o777;
    if raw_mode != 0o600 {
        let err = verify_socket_endpoint_for_connect(&socket_str, euid).unwrap_err();
        assert!(
            matches!(err, IpcError::Unauthenticated { .. }),
            "non-0600 BITTY_SOCKET endpoint must fail closed, got: {err:?}"
        );
    }
    std::fs::set_permissions(&socket_str, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(verify_socket_endpoint_for_connect(&socket_str, euid).is_ok());

    // Shape violations still fail at resolution (fail-closed, no verify needed).
    assert!(resolve_socket_path(1000, None, Some("/tmp/a\0b.sock"), None).is_err());
    let long = "x".repeat(MAX_SOCKET_PATH_BYTES + 1);
    assert!(resolve_socket_path(1000, None, Some(&long), None).is_err());
    // Shape violations fail at verification too.
    assert!(verify_socket_endpoint_for_connect("", euid).is_err());
    assert!(verify_socket_endpoint_for_connect("/tmp/a\0b.sock", euid).is_err());

    drop(listener);
    std::fs::remove_dir_all(&base).ok();
}

// ── introspection (CTX-0159, read-only, bounded) ───────────────────────
//
// The global live stores (`live_grid_store`, `live_input_store`, ...) are
// shared across tests in this binary. Rust runs tests in parallel
// threads, so one test's `clear_introspection_for_tests` can wipe another
// test's published snapshot mid-sequence (CTX-0179 CI flake: 134 passed /
// 1 failed on `introspection_round_trip_all_methods_sequential`). Every
// test below that touches the globals holds
// `lock_introspection_for_test` for its whole publish→assert sequence;
// tests that only exercise pure parsers need no guard. Test-only:
// production paths never take this lock (lock order is always
// serial-guard → store locks, never the reverse, so no deadlock).

/// Serial guard for the process-global live introspection stores.
///
/// std-only on purpose (`serial_test` would add a dev-dependency for
/// what is ten lines): same `OnceLock<Mutex<...>>` idiom as the stores
/// themselves. Poison-safe so a panicking holder cannot cascade-fail the
/// rest of the suite.
fn introspection_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Hold for the whole body of any test that publishes, reads, or clears
/// the global introspection stores.
fn lock_introspection_for_test() -> std::sync::MutexGuard<'static, ()> {
    introspection_test_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn introspection_params_are_per_method_bounded() {
    // Absent params mean defaults.
    assert_eq!(
        parse_optional_uint_param(None, "rows", MAX_INSPECT_ROWS, MAX_INSPECT_ROWS).unwrap(),
        MAX_INSPECT_ROWS
    );
    // Present and valid.
    assert_eq!(
        parse_optional_uint_param(
            Some(r#"{"rows":10,"cols":40}"#),
            "rows",
            MAX_INSPECT_ROWS,
            MAX_INSPECT_ROWS
        )
        .unwrap(),
        10
    );
    assert_eq!(
        parse_optional_uint_param(
            Some(r#"{"limit":5}"#),
            "limit",
            MAX_INPUT_RING,
            MAX_INPUT_RING
        )
        .unwrap(),
        5
    );
    // Unknown keys are ignored (forward compatible).
    assert_eq!(
        parse_optional_uint_param(
            Some(r#"{"other":99}"#),
            "rows",
            MAX_INSPECT_ROWS,
            MAX_INSPECT_ROWS
        )
        .unwrap(),
        MAX_INSPECT_ROWS
    );
    // Oversize, zero, non-numeric, and signed values fail closed.
    assert!(
        parse_optional_uint_param(
            Some(r#"{"rows":999}"#),
            "rows",
            MAX_INSPECT_ROWS,
            MAX_INSPECT_ROWS
        )
        .is_err()
    );
    assert!(
        parse_optional_uint_param(
            Some(r#"{"rows":0}"#),
            "rows",
            MAX_INSPECT_ROWS,
            MAX_INSPECT_ROWS
        )
        .is_err()
    );
    assert!(
        parse_optional_uint_param(
            Some(r#"{"rows":"10"}"#),
            "rows",
            MAX_INSPECT_ROWS,
            MAX_INSPECT_ROWS
        )
        .is_err()
    );
    assert!(
        parse_optional_uint_param(
            Some(r#"{"rows":-3}"#),
            "rows",
            MAX_INSPECT_ROWS,
            MAX_INSPECT_ROWS
        )
        .is_err()
    );
}

#[test]
fn introspection_envelope_params_shape() {
    // Object params are captured verbatim for handlers.
    let request = parse_request(
        br#"{"id":1,"method":"bitty.debug/getGridText","version":"1.0","params":{"rows":10}}"#,
    )
    .unwrap();
    assert_eq!(request.params_raw.as_deref(), Some(r#"{"rows":10}"#));
    // Absent params yield None (defaults apply).
    let request =
        parse_request(br#"{"id":1,"method":"bitty.debug/getGridText","version":"1.0"}"#).unwrap();
    assert_eq!(request.params_raw, None);
    // Array params fail closed.
    let fault = parse_request(
        br#"{"id":2,"method":"bitty.debug/getGridText","version":"1.0","params":[1]}"#,
    )
    .unwrap_err();
    assert_eq!(fault.code, "InvalidParams");
    // Oversize params fail closed before dispatch.
    let big = format!(
        "{{\"id\":3,\"method\":\"bitty.debug/getGridText\",\"version\":\"1.0\",\"params\":{{\"pad\":\"{}\"}}}}",
        "p".repeat(MAX_PARAMS_BYTES)
    );
    let fault = parse_request(big.as_bytes()).unwrap_err();
    assert_eq!(fault.code, "PayloadTooLarge");
}

#[test]
fn introspection_round_trip_all_methods_sequential() {
    let _introspection_guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    publish_grid_text(
        vec!["hello introspect".to_string(), "second row".to_string()],
        0,
        16,
        true,
        7,
        80,
        24,
    );
    publish_input_ring(vec![
        InputEventPublish {
            seq: 1,
            kind: "key".to_string(),
            label: "key:a".to_string(),
            shift: false,
            control: false,
            alt: false,
            button: None,
            col: None,
            row: None,
            pressed: Some(true),
        },
        InputEventPublish {
            seq: 2,
            kind: "mouse".to_string(),
            label: "mouse:Left pressed col=10 row=5".to_string(),
            shift: false,
            control: false,
            alt: false,
            button: Some("Left".to_string()),
            col: Some(10),
            row: Some(5),
            pressed: Some(true),
        },
    ]);
    publish_modifiers(ModifiersPublish {
        shift: true,
        control: false,
        alt: false,
        enhanced_keyboard_flags: 0,
    });
    publish_focus(FocusPublish {
        focused: true,
        focused_view: Some(1),
        mouse_capture: false,
        alt_screen: false,
        bracketed_paste: false,
        focus_events: false,
    });

    let dispatcher = Dispatcher::with_defaults();
    let context = test_context();

    let outcome = handle_envelope(
        br#"{"id":1,"method":"bitty.debug/getGridText","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("\"snapshot\":\"grid-text\""));
    assert!(text.contains("hello introspect"));
    assert!(text.contains("\"row\":0"));

    // Bounded slice via params.
    let outcome = handle_envelope(
        br#"{"id":2,"method":"bitty.debug/getGridText","version":"1.0","params":{"rows":1,"cols":5}}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("hello"));

    let outcome = handle_envelope(
        br#"{"id":3,"method":"bitty.debug/getInputRing","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("\"snapshot\":\"input-ring\""));
    assert!(text.contains("key:a"));
    assert!(text.contains("mouse:Left"));

    let outcome = handle_envelope(
        br#"{"id":4,"method":"bitty.debug/getInputRing","version":"1.0","params":{"limit":1}}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("mouse:Left"));
    assert!(!text.contains("key:a"));

    let outcome = handle_envelope(
        br#"{"id":5,"method":"bitty.debug/getModifiers","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("\"snapshot\":\"modifiers\""));
    assert!(text.contains("\"shift\":true"));

    let outcome = handle_envelope(
        br#"{"id":6,"method":"bitty.debug/getFocus","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("\"snapshot\":\"focus\""));
    assert!(text.contains("\"focused\":true"));

    // Oversize params fail closed with correlated errors.
    let outcome = handle_envelope(
        br#"{"id":7,"method":"bitty.debug/getGridText","version":"1.0","params":{"rows":999}}"#,
        &dispatcher,
        &context,
    );
    assert!(outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("InvalidParams"));
    assert!(text.contains("\"id\":7"));

    clear_introspection_for_tests();
}

#[test]
fn introspection_empty_store_is_not_an_error() {
    let _introspection_guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    let dispatcher = Dispatcher::with_defaults();
    let context = test_context();
    let outcome = handle_envelope(
        br#"{"id":1,"method":"bitty.debug/getGridText","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("\"lines\":[]"));
    let outcome = handle_envelope(
        br#"{"id":2,"method":"bitty.debug/getInputRing","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("\"events\":[]")
    );
    clear_introspection_for_tests();
}

#[test]
fn introspection_publish_is_bounded() {
    let _introspection_guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    // Overlong grid input is truncated deterministically at publish time.
    let long_line = "x".repeat(MAX_INSPECT_COLS + 50);
    let many: Vec<String> = (0..(MAX_INSPECT_ROWS + 10))
        .map(|i| format!("{long_line}-{i}"))
        .collect();
    publish_grid_text(many, 0, 0, true, 1, 80, 24);
    let dispatcher = Dispatcher::with_defaults();
    let context = test_context();
    let outcome = handle_envelope(
        br#"{"id":1,"method":"bitty.debug/getGridText","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.len() <= MAX_INSPECT_JSON_BYTES + 512);
    // Overlong labels are truncated at publish time.
    publish_input_ring(vec![InputEventPublish {
        seq: 1,
        kind: "key".to_string(),
        label: "y".repeat(MAX_INPUT_LABEL_CHARS + 100),
        shift: false,
        control: false,
        alt: false,
        button: None,
        col: None,
        row: None,
        pressed: Some(true),
    }]);
    let outcome = handle_envelope(
        br#"{"id":2,"method":"bitty.debug/getInputRing","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.len() <= MAX_INSPECT_JSON_BYTES + 512);
    clear_introspection_for_tests();
}

// ── debug-protocol v1 verification (CTX-0589, issue #1097) ──────────────
//
// Contract-level evidence for the devtools-rfc plugin-runtime verification
// plan that is reachable on today's server surface:
// - P0-AC-025 zero-scope matrix: connection (an empty granted set) grants
//   none of `debug.inspect`/`debug.trace`/`debug.control`; every read method
//   fails closed with a typed `scope`/`ScopeDenied`, zero partial state.
// - Typed-error taxonomy: every server failure carries a category drawn from
//   the accepted set (`usage`|`capability`|`scope`|`budget`|`generation`|
//   `transport`), never an off-taxonomy class. Pins the control-denial
//   mapping (`auth` -> `scope`).
// The RFC's plugin-runtime methods (`listPlugins`, `getPlugin`,
// `getBudgets`, `disposeGeneration`, ...) are registered on this server
// slice as scope- and param-gated fail-closed stubs (issue #1377): no
// plugin host lives in this crate, so valid calls fail closed with
// `capability`/`PluginRuntimeUnavailable` instead of leaking or inventing
// data. Their generation-ownership acceptance items are covered by the
// `(pluginId, generation)` param gates pinned below; the generation
// invariant that IS reachable (grid `generation` is output-only,
// with no caller-supplied stale-generation parameter) is pinned below.

/// Accepted error categories per devtools-rfc (L331-333): every failure must
/// carry one of these on the wire.
const ACCEPTED_DEBUG_CATEGORIES: &[&str] = &[
    "usage",
    "capability",
    "scope",
    "budget",
    "generation",
    "transport",
];

/// Extract the `error.category` value from a rendered error response.
fn error_category(response: &str) -> Option<String> {
    let at = response.find("\"category\":\"")? + "\"category\":\"".len();
    let rest = &response[at..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[test]
fn debug_read_surface_connection_alone_grants_nothing() {
    // P0-AC-025 read half: a peer that has merely connected (empty granted
    // set) must be denied every read method with the shared typed shape and
    // zero partial state.
    let _introspection_guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    publish_grid_text(vec!["SECRET-GRID".to_string()], 0, 0, true, 5, 80, 24);
    let dispatcher = Dispatcher::with_defaults();
    let ctx =
        ServeContext::with_granted_for_tests(&test_server_info(), crate::scope::ScopeSet::new());
    for method in [
        "bitty.debug/getSnapshot",
        "bitty.debug/getGridText",
        "bitty.debug/getInputRing",
        "bitty.debug/getModifiers",
        "bitty.debug/getFocus",
    ] {
        let envelope =
            format!("{{\"id\":1,\"method\":\"{method}\",\"version\":\"1.0\"}}").into_bytes();
        let outcome = handle_envelope(&envelope, &dispatcher, &ctx);
        assert!(
            outcome.was_error,
            "{method} must be denied with zero scopes"
        );
        let text = response_text(&outcome);
        assert_eq!(
            error_category(&text).as_deref(),
            Some("scope"),
            "{method} denial must be typed scope: {text}"
        );
        assert!(
            text.contains("\"code\":\"ScopeDenied\""),
            "{method} denial must be ScopeDenied: {text}"
        );
        assert!(
            !text.contains("SECRET-GRID"),
            "{method} must not leak content on a denial: {text}"
        );
    }
    clear_introspection_for_tests();
}

#[test]
fn terminal_content_requires_debug_and_terminal_capability_intersection() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    publish_grid_text(
        vec!["CAPABILITY-SENTINEL".to_string()],
        0,
        0,
        true,
        1,
        80,
        24,
    );
    let dispatcher = Dispatcher::with_defaults();
    let authority = crate::ctl::ControlAuthority::new();
    let grant = authority
        .open_connection(
            crate::scope::ScopeSet::single(crate::scope::Scope::DebugInspect),
            crate::ctl::TerminalCapabilities::new(),
        )
        .expect("connection grant");
    let context = ServeContext::with_connection_grant_for_tests(&test_server_info(), grant);
    let outcome = handle_envelope(
        br#"{"id":1,"method":"bitty.debug/getGridText","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(outcome.was_error);
    let text = response_text(&outcome);
    assert!(text.contains("ScopeDenied"));
    assert!(!text.contains("CAPABILITY-SENTINEL"));
    let malformed = handle_envelope(
        br#"{"id":2,"method":"bitty.debug/getGridText","version":"1.0","params":{"terminalId":"not-a-terminal"}}"#,
        &dispatcher,
        &ServeContext::with_granted_for_tests(
            &test_server_info(),
            crate::scope::ScopeSet::all(),
        ),
    );
    assert!(malformed.was_error);
    assert!(response_text(&malformed).contains("InvalidParams"));
    assert!(!response_text(&malformed).contains("CAPABILITY-SENTINEL"));
    clear_introspection_for_tests();
}

/// CTX-0792 / #1404: the full debug-scope × terminal-capability matrix for
/// every terminal-reading debug surface. The stores are not attributed to one
/// terminal, so a narrowed per-terminal entry denies the read whether or not
/// the request names a terminal, and a map entry can never stand in for a
/// scope the session does not hold.
#[test]
fn terminal_read_surfaces_deny_without_the_full_intersection() {
    use crate::ctl::{ControlAuthority, TerminalCapabilities};
    use crate::scope::{Scope, ScopeSet};

    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    publish_grid_text(vec!["MATRIX-SENTINEL".to_string()], 0, 0, true, 1, 80, 24);
    let dispatcher = Dispatcher::with_defaults();
    let methods = [
        "bitty.debug/getSnapshot",
        "bitty.debug/getGridText",
        "bitty.debug/getInputRing",
        "bitty.debug/getModifiers",
        "bitty.debug/getFocus",
    ];
    let set = |scopes: &[Scope]| {
        let mut out = ScopeSet::new();
        for scope in scopes {
            out.insert(*scope);
        }
        out
    };
    let debug_only = set(&[Scope::DebugInspect]);
    let terminal_only = set(&[Scope::TerminalInspect]);
    let both = set(&[Scope::DebugInspect, Scope::TerminalInspect]);
    let mut narrowed = TerminalCapabilities::from_scopes(&both);
    // t:2 keeps an entry without `terminal.inspect` (input only).
    narrowed.grant("t:2", Scope::TerminalInput).expect("entry");
    let mut both_with_input = both.clone();
    both_with_input.insert(Scope::TerminalInput);
    let cases: [(&str, ScopeSet, TerminalCapabilities, bool); 5] = [
        (
            "debug only",
            debug_only.clone(),
            TerminalCapabilities::from_scopes(&debug_only),
            false,
        ),
        (
            "terminal only",
            terminal_only.clone(),
            TerminalCapabilities::from_scopes(&terminal_only),
            false,
        ),
        // A map that claims `terminal.inspect` is clamped to the session's scopes.
        (
            "map without scope",
            debug_only.clone(),
            TerminalCapabilities::from_scopes(&both),
            false,
        ),
        ("narrowed terminal entry", both_with_input, narrowed, false),
        (
            "debug and terminal",
            both.clone(),
            TerminalCapabilities::from_scopes(&both),
            true,
        ),
    ];
    for (label, scopes, capabilities, allowed) in cases {
        let grant = ControlAuthority::new()
            .open_connection(scopes, capabilities)
            .expect("connection grant");
        let context = ServeContext::with_connection_grant_for_tests(&test_server_info(), grant);
        for method in methods {
            for params in [
                "",
                r#","params":{"terminalId":"t:1"}"#,
                r#","params":{"terminalId":"t:2"}"#,
            ] {
                let frame = format!(r#"{{"id":1,"method":"{method}","version":"1.0"{params}}}"#);
                let outcome = handle_envelope(frame.as_bytes(), &dispatcher, &context);
                let text = response_text(&outcome);
                if allowed {
                    assert!(
                        !outcome.was_error,
                        "{label}: {method}{params} must pass: {text}"
                    );
                } else {
                    assert!(outcome.was_error, "{label}: {method}{params} must deny");
                    assert!(
                        text.contains("ScopeDenied"),
                        "{label}: {method}{params}: {text}"
                    );
                    assert!(
                        !text.contains("MATRIX-SENTINEL"),
                        "{label}: {method} leaked data"
                    );
                }
            }
        }
    }
    clear_introspection_for_tests();
}

#[test]
fn revoked_connection_loses_protected_debug_surface() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    publish_grid_text(vec!["REVOKED-SENTINEL".to_string()], 0, 0, true, 1, 80, 24);
    let dispatcher = Dispatcher::with_defaults();
    let authority = crate::ctl::ControlAuthority::new();
    let mut scopes = crate::scope::ScopeSet::new();
    scopes.insert(crate::scope::Scope::DebugInspect);
    scopes.insert(crate::scope::Scope::TerminalInspect);
    let capabilities = crate::ctl::TerminalCapabilities::from_scopes(&scopes);
    let grant = authority
        .open_connection(scopes, capabilities)
        .expect("connection grant");
    let session_id = grant.session_id().to_string();
    let context = ServeContext::with_connection_grant_for_tests(&test_server_info(), grant);
    let before = handle_envelope(
        br#"{"id":1,"method":"bitty.debug/getGridText","version":"1.0","params":{"terminalId":"t:1"}}"#,
        &dispatcher,
        &context,
    );
    assert!(!before.was_error);
    assert!(response_text(&before).contains("REVOKED-SENTINEL"));
    assert!(authority.revoke_scope(&session_id, crate::scope::Scope::DebugInspect));
    let after = handle_envelope(
        br#"{"id":2,"method":"bitty.debug/getGridText","version":"1.0","params":{"terminalId":"t:1"}}"#,
        &dispatcher,
        &context,
    );
    assert!(after.was_error);
    let text = response_text(&after);
    assert!(text.contains("ScopeDenied"));
    assert!(!text.contains("REVOKED-SENTINEL"));
    let plugin = handle_envelope(
        br#"{"id":3,"method":"bitty.debug/listPlugins","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(plugin.was_error);
    assert!(response_text(&plugin).contains("ScopeDenied"));
    clear_introspection_for_tests();
}

#[test]
fn debug_read_surface_any_debug_scope_reads_but_others_do_not() {
    // The accepted hierarchy is debug.control > debug.trace > debug.inspect
    // (RFC scopes table), so any one debug scope reads the surface; a peer
    // holding only a non-debug scope does not.
    let _introspection_guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    publish_grid_text(vec!["readable".to_string()], 0, 0, true, 5, 80, 24);
    let dispatcher = Dispatcher::with_defaults();
    for scope in [
        crate::scope::Scope::DebugInspect,
        crate::scope::Scope::DebugTrace,
        crate::scope::Scope::DebugControl,
    ] {
        let mut granted = crate::scope::ScopeSet::new();
        granted.insert(scope);
        // The debug read surface is the intersection of a debug scope with
        // `terminal.inspect` (CTX-0792 #1404 narrowing, DEC-0073), so the
        // capability is declared explicitly here to isolate the debug-scope
        // dimension this test is about.
        granted.insert(crate::scope::Scope::TerminalInspect);
        // `with_granted_for_tests` is the hermetic seam that keeps dispatch
        // open without a bound peer proof (CTX-0768 `test_dispatch`).
        let ctx = ServeContext::with_granted_for_tests(&test_server_info(), granted);
        let outcome = handle_envelope(
            br#"{"id":1,"method":"bitty.debug/getGridText","version":"1.0"}"#,
            &dispatcher,
            &ctx,
        );
        assert!(!outcome.was_error, "{scope:?} must read the grid surface");
        assert!(response_text(&outcome).contains("readable"));
    }
    let mut non_debug = crate::scope::ScopeSet::new();
    non_debug.insert(crate::scope::Scope::TerminalInspect);
    let ctx = ServeContext::with_granted_for_tests(&test_server_info(), non_debug);
    let outcome = handle_envelope(
        br#"{"id":1,"method":"bitty.debug/getGridText","version":"1.0"}"#,
        &dispatcher,
        &ctx,
    );
    assert!(
        outcome.was_error,
        "terminal.inspect must not read debug surface"
    );
    assert!(response_text(&outcome).contains("ScopeDenied"));
    clear_introspection_for_tests();
}

#[test]
fn debug_control_denial_category_is_on_taxonomy() {
    // Regression: the control path's internal `auth` CLI class must not leak
    // onto the debug wire; a scope denial is typed `scope` (RFC taxonomy).
    let dispatcher = Dispatcher::with_defaults();
    let ctx =
        ServeContext::with_granted_for_tests(&test_server_info(), crate::scope::ScopeSet::new());
    let outcome = handle_envelope(
        br#"{"id":1,"method":"bitty.debug/spawnTerminal","version":"1.0","params":{"cwd":null}}"#,
        &dispatcher,
        &ctx,
    );
    assert!(outcome.was_error);
    let text = response_text(&outcome);
    assert_eq!(
        error_category(&text).as_deref(),
        Some("scope"),
        "control denial must map auth -> scope: {text}"
    );
    assert!(
        text.contains("\"code\":\"ScopeDenied\""),
        "control denial must keep ScopeDenied: {text}"
    );
}

#[test]
fn debug_error_categories_stay_on_taxonomy() {
    // Typed-error sweep: every reachable server failure category is in the
    // accepted set. Drives the same dispatcher through parse faults, scope
    // denials, unknown methods, and version faults.
    let dispatcher = Dispatcher::with_defaults();
    let ctx =
        ServeContext::with_granted_for_tests(&test_server_info(), crate::scope::ScopeSet::new());
    let probes: &[&[u8]] = &[
        br#"{"id":1,"method":"bitty.debug/nope","version":"1.0"}"#,
        br#"{"id":2,"method":"bitty.debug/ping","version":"9.9"}"#,
        br#"{"id":3,"method":"bitty.debug/ping","version":"1.0","scope":"admin"}"#,
        br#"{"id":4,"method":"bitty.debug/spawnTerminal","version":"1.0","params":{"cwd":null}}"#,
        br#"{"id":5,"method":"bitty.debug/getGridText","version":"1.0"}"#,
        br#"{"id":6,"method":"bitty.debug/getGridText","version":"1.0","params":{"rows":999}}"#,
    ];
    for payload in probes {
        let outcome = handle_envelope(payload, &dispatcher, &ctx);
        assert!(
            outcome.was_error,
            "probe must fail: {:?}",
            response_text(&outcome)
        );
        let text = response_text(&outcome);
        let category = error_category(&text).expect("error must carry a category");
        assert!(
            ACCEPTED_DEBUG_CATEGORIES.contains(&category.as_str()),
            "off-taxonomy category {category:?}: {text}"
        );
    }
}

#[test]
fn grid_generation_is_output_only_no_caller_generation_param() {
    // Generation ownership at the reachable debug boundary: the grid
    // `generation` is a damage-generation output. There is no caller-supplied
    // generation parameter that could address another generation's data, so a
    // stale-generation request cannot leak a sibling scope's content. A
    // caller-supplied `generation` is ignored (not an address).
    let _introspection_guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    publish_grid_text(vec!["gen-seven".to_string()], 0, 0, true, 7, 80, 24);
    let dispatcher = Dispatcher::with_defaults();
    let context = test_context();
    let outcome = handle_envelope(
        br#"{"id":1,"method":"bitty.debug/getGridText","version":"1.0","params":{"generation":3}}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    let text = response_text(&outcome);
    assert!(
        text.contains("\"generation\":7"),
        "served generation must be the live store's, not the caller's: {text}"
    );
    assert!(
        !text.contains("\"generation\":3"),
        "a caller-supplied generation must not be echoed as authority: {text}"
    );
    clear_introspection_for_tests();
}

// ── test automation (CTX-0188, Amendment A1 candidate) ──────────────────
//
// Bearer matrix, scope intersection, bounds, redaction, and rate shedding
// for `synthesizeInput` + `captureFrame`. Every test holds the serial
// guard (automation shares the input/grid stores) and clears automation
// plus introspection before and after.

fn automation_scopes_synthesize() -> crate::scope::ScopeSet {
    let mut set = crate::scope::ScopeSet::new();
    set.insert(crate::scope::Scope::DebugControl);
    set.insert(crate::scope::Scope::TerminalInput);
    set
}

fn automation_scopes_capture() -> crate::scope::ScopeSet {
    let mut set = crate::scope::ScopeSet::new();
    set.insert(crate::scope::Scope::DebugTrace);
    set.insert(crate::scope::Scope::TerminalInspect);
    set
}

fn automation_context(
    server: &ServerInfo,
    granted: crate::scope::ScopeSet,
    session: &str,
    now_ms: u64,
) -> ServeContext {
    let mut ctx = ServeContext::with_granted_session_for_tests(server, granted, session);
    ctx.uptime_ms = now_ms;
    ctx
}

fn synth_envelope(id: u64, params: &str) -> Vec<u8> {
    format!(
        "{{\"id\":{id},\"method\":\"{METHOD_SYNTHESIZE_INPUT}\",\"version\":\"1.0\",\"params\":{params}}}"
    )
    .into_bytes()
}

fn capture_envelope(id: u64, params: &str) -> Vec<u8> {
    format!(
        "{{\"id\":{id},\"method\":\"{METHOD_CAPTURE_FRAME}\",\"version\":\"1.0\",\"params\":{params}}}"
    )
    .into_bytes()
}

// ── frameHash digest (CTX-0244) ─────────────────────────────────────────
//
// Digest equality vs local computation, full denial matrix, TTL cap,
// 2/s rate ceiling, fail-closed publish validation, bounded audit with
// served-digest content, and no-bypass isolation in both family
// directions. Every test holds the serial guard and clears automation
// plus introspection (incl. the RGBA store) before and after. All
// content is synthetic fixture bytes — never secrets (P0-AC-026
// harness rule).

fn digest_envelope(id: u64, params: &str) -> Vec<u8> {
    format!(
        "{{\"id\":{id},\"method\":\"{METHOD_FRAME_HASH}\",\"version\":\"1.0\",\"params\":{params}}}"
    )
    .into_bytes()
}

fn digest_context(
    server: &ServerInfo,
    granted: crate::scope::ScopeSet,
    session: &str,
    now_ms: u64,
) -> ServeContext {
    // Same marker type as a connected-stream binding; same-process
    // in-process dispatch is local by construction. CTX-0528/IPC-001: the
    // mark is bound to a test-only marker minted via the headless UID check.
    let mut ctx = automation_context(server, granted, session, now_ms);
    let peer = crate::auth::verify_peer_for_connection(
        crate::auth::PeerCredentials::new(1000, 1000, 1),
        1000,
    )
    .expect("test-only local marker");
    ctx.attest_local_peer(&peer);
    ctx
}

/// Deterministic synthetic RGBA fixture (never secrets): a gradient
/// over `w*h*4` bytes with an ASCII marker row to prove no pixel bytes
/// reach the response.
fn fixture_rgba(width: u32, height: u32, seed: u8) -> Vec<u8> {
    let len = width as usize * height as usize * 4;
    let mut rgba = Vec::with_capacity(len);
    for i in 0..len {
        rgba.push(
            (i as u8)
                .wrapping_add(seed)
                .wrapping_mul(31)
                .wrapping_add(7),
        );
    }
    // ASCII marker the response must never contain (uninvertibility
    // spot-check, not a proof — the proof is the 32-byte digest).
    let marker = b"FRAMEHASH-MARKER-NEVER-ON-WIRE";
    let at = len.min(256);
    for (i, b) in marker.iter().enumerate() {
        if at + i < len {
            rgba[at + i] = *b;
        }
    }
    rgba
}

fn response_text(outcome: &HandleOutcome) -> String {
    String::from_utf8(outcome.response.clone()).unwrap()
}

#[test]
fn frame_hash_digest_equals_local_computation_across_geometries() {
    use crate::frame_digest::{FRAME_DIGEST_ALGO, frame_digest_hex};
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    // Three geometries (tiny, odd-sized, and multi-kilopixel) with
    // distinct seeds and frame sequences.
    for (id, (w, h, seq, seed)) in [(80u32, 60u32, 9u64, 1u8), (17, 5, 41, 2), (320, 200, 7, 3)]
        .into_iter()
        .enumerate()
    {
        let rgba = fixture_rgba(w, h, seed);
        publish_frame_rgba(w, h, seq, rgba.clone());
        publish_grid_text(vec!["synthetic".to_string()], 0, 0, true, seq, 80, 24);
        let tok = issue_automation_bearer_with_ttl(
            "digest-eq",
            "t:1",
            AutomationFamily::FrameDigest,
            0,
            60_000,
        )
        .unwrap();
        let ctx = digest_context(&server, automation_scopes_capture(), "digest-eq", 0);
        let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\"}}");
        let outcome = handle_envelope(&digest_envelope(id as u64 + 1, &params), &dispatcher, &ctx);
        assert!(!outcome.was_error, "geometry {w}x{h} must verify");
        let text = response_text(&outcome);
        let expect = frame_digest_hex(w, h, seq, &rgba);
        assert!(text.contains("\"snapshot\":\"frameHash\""), "got: {text}");
        assert!(
            text.contains(&format!("\"algo\":\"{FRAME_DIGEST_ALGO}\"")),
            "got: {text}"
        );
        assert!(
            text.contains(&format!("\"digest\":\"{expect}\"")),
            "digest mismatch at {w}x{h}: {text}"
        );
        assert!(text.contains(&format!("\"frameSeq\":{seq}")), "got: {text}");
        assert!(
            text.contains("\"trust\":\"untrusted-observation\""),
            "got: {text}"
        );
        assert!(text.len() < 512, "digest response must stay tiny: {text}");
        assert!(
            !text.contains("FRAMEHASH-MARKER-NEVER-ON-WIRE"),
            "pixel bytes reached the wire: {text}"
        );
        clear_automation_for_tests();
    }
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn frame_hash_auth_matrix_denies_everything_unauthorized() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    publish_frame_rgba(8, 8, 3, fixture_rgba(8, 8, 9));
    let digest_tok =
        issue_automation_bearer_with_ttl("m", "t:1", AutomationFamily::FrameDigest, 0, 60_000)
            .unwrap();
    let capture_tok = issue_automation_bearer("m", "t:1", AutomationFamily::Capture, 0).unwrap();

    // (label, scopes, session, terminal-in-params, token, now, attest)
    let full = automation_scopes_capture();
    let mut no_trace = automation_scopes_capture();
    no_trace.remove(crate::scope::Scope::DebugTrace);
    let mut no_inspect = automation_scopes_capture();
    no_inspect.remove(crate::scope::Scope::TerminalInspect);
    let cases: Vec<(&str, crate::scope::ScopeSet, &str, &str, String, u64, bool)> = vec![
        (
            "no-bearer",
            full.clone(),
            "m",
            "t:1",
            String::new(),
            0,
            true,
        ),
        (
            "wrong-family-capture-token",
            full.clone(),
            "m",
            "t:1",
            capture_tok.clone(),
            0,
            true,
        ),
        (
            "wrong-terminal",
            full.clone(),
            "m",
            "t:2",
            digest_tok.clone(),
            0,
            true,
        ),
        (
            "wrong-session",
            full.clone(),
            "other",
            "t:1",
            digest_tok.clone(),
            0,
            true,
        ),
        (
            "missing-debug-trace",
            no_trace,
            "m",
            "t:1",
            digest_tok.clone(),
            0,
            true,
        ),
        (
            "missing-terminal-inspect",
            no_inspect,
            "m",
            "t:1",
            digest_tok.clone(),
            0,
            true,
        ),
        (
            "unattested-transport",
            full.clone(),
            "m",
            "t:1",
            digest_tok.clone(),
            0,
            false,
        ),
        (
            "forged-token-full-scopes",
            crate::scope::ScopeSet::all(),
            "m",
            "t:1",
            "forged-token".to_string(),
            0,
            true,
        ),
    ];
    for (label, scopes, session, term, token, now, attest) in cases {
        let mut ctx = automation_context(&server, scopes, session, now);
        if attest {
            // CTX-0528/IPC-001: attestation requires the verified marker —
            // same-process dispatch mints it via the headless UID check.
            let peer = crate::auth::verify_peer_for_connection(
                crate::auth::PeerCredentials::new(1000, 1000, 1),
                1000,
            )
            .expect("test-only local marker");
            ctx.attest_local_peer(&peer);
        }
        let params = if token.is_empty() {
            format!("{{\"terminalId\":\"{term}\"}}")
        } else {
            format!("{{\"terminalId\":\"{term}\",\"bearer\":\"{token}\"}}")
        };
        let outcome = handle_envelope(&digest_envelope(1, &params), &dispatcher, &ctx);
        assert!(outcome.was_error, "{label} must fail");
        assert!(
            response_text(&outcome).contains("ScopeDenied"),
            "{label}: bearer-vs-scope failures must share the ScopeDenied shape, got: {}",
            response_text(&outcome)
        );
    }
    // Malformed shape fails closed without attribution (no audit needed).
    let ctx = digest_context(&server, automation_scopes_capture(), "m", 0);
    let outcome = handle_envelope(&digest_envelope(2, "{}"), &dispatcher, &ctx);
    assert!(response_text(&outcome).contains("InvalidParams"));
    let outcome = handle_envelope(
        &digest_envelope(3, r#"{"terminalId":"t:*"}"#),
        &dispatcher,
        &ctx,
    );
    assert!(response_text(&outcome).contains("InvalidParams"));
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn frame_hash_ttl_capped_at_two_minutes_and_expiry_revokes() {
    use crate::frame_digest::FRAME_DIGEST_TTL_MS;
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    assert_eq!(FRAME_DIGEST_TTL_MS, 120_000);
    // The default 10-minute minter refuses digest grants fail-closed:
    // a digest TTL must be explicit.
    assert!(issue_automation_bearer("ttl", "t:1", AutomationFamily::FrameDigest, 0).is_err());
    // Zero and over-cap TTLs fail closed.
    assert!(
        issue_automation_bearer_with_ttl("ttl", "t:1", AutomationFamily::FrameDigest, 0, 0)
            .is_err()
    );
    assert!(
        issue_automation_bearer_with_ttl(
            "ttl",
            "t:1",
            AutomationFamily::FrameDigest,
            0,
            FRAME_DIGEST_TTL_MS + 1
        )
        .is_err()
    );
    // Cap edge issues; sibling families still enjoy the 10-minute cap.
    let tok = issue_automation_bearer_with_ttl(
        "ttl",
        "t:1",
        AutomationFamily::FrameDigest,
        500,
        FRAME_DIGEST_TTL_MS,
    )
    .unwrap();
    assert!(
        issue_automation_bearer_with_ttl(
            "ttl",
            "t:1",
            AutomationFamily::Synthesize,
            0,
            AUTOMATION_BEARER_TTL_MS
        )
        .is_ok()
    );
    // Grant valid at issuance, denied exactly at issue+TTL
    // (virtual clock: no sleeps, no wall-clock).
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    publish_frame_rgba(4, 4, 1, fixture_rgba(4, 4, 5));
    let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\"}}");
    let ctx = digest_context(&server, automation_scopes_capture(), "ttl", 500);
    let outcome = handle_envelope(&digest_envelope(1, &params), &dispatcher, &ctx);
    assert!(!outcome.was_error, "grant must verify at issuance");
    let ctx = digest_context(
        &server,
        automation_scopes_capture(),
        "ttl",
        500 + FRAME_DIGEST_TTL_MS,
    );
    let outcome = handle_envelope(&digest_envelope(2, &params), &dispatcher, &ctx);
    assert!(outcome.was_error);
    assert!(
        response_text(&outcome).contains("ScopeDenied"),
        "expired digest grant must deny: {}",
        response_text(&outcome)
    );
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn frame_hash_rate_sheds_third_digest_per_second() {
    use crate::frame_digest::MAX_FRAME_DIGEST_PER_SEC;
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    assert_eq!(MAX_FRAME_DIGEST_PER_SEC, 2);
    publish_frame_rgba(4, 4, 1, fixture_rgba(4, 4, 5));
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let tok =
        issue_automation_bearer_with_ttl("rl", "t:1", AutomationFamily::FrameDigest, 0, 60_000)
            .unwrap();
    let ctx = digest_context(&server, automation_scopes_capture(), "rl", 0);
    let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\"}}");
    for id in 1..=MAX_FRAME_DIGEST_PER_SEC as u64 {
        let outcome = handle_envelope(&digest_envelope(id, &params), &dispatcher, &ctx);
        assert!(!outcome.was_error, "digest {id} must pass under ceiling");
    }
    let outcome = handle_envelope(
        &digest_envelope(MAX_FRAME_DIGEST_PER_SEC as u64 + 1, &params),
        &dispatcher,
        &ctx,
    );
    assert!(outcome.was_error);
    assert!(
        response_text(&outcome).contains("RateLimited"),
        "third digest in one window must shed: {}",
        response_text(&outcome)
    );
    // Window slides: one second later the ceiling admits again.
    let ctx = digest_context(&server, automation_scopes_capture(), "rl", 1_000);
    let outcome = handle_envelope(&digest_envelope(9, &params), &dispatcher, &ctx);
    assert!(!outcome.was_error, "window must slide after 1 s");
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn frame_hash_unavailable_without_presented_frame_and_rejects_bad_publish() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let tok =
        issue_automation_bearer_with_ttl("np", "t:1", AutomationFamily::FrameDigest, 0, 60_000)
            .unwrap();
    // Authorized-but-unavailable calls still consume the rate budget
    // (authorize runs first), so each probe advances the virtual clock.
    let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\"}}");
    // Never a hash of nothing: empty store reads as indeterminate.
    let ctx = digest_context(&server, automation_scopes_capture(), "np", 0);
    let outcome = handle_envelope(&digest_envelope(1, &params), &dispatcher, &ctx);
    assert!(outcome.was_error);
    assert!(
        response_text(&outcome).contains("Unavailable"),
        "got: {}",
        response_text(&outcome)
    );
    // Fail-closed publish validation: zero extents, length mismatch,
    // and over-cap frames never become digestable.
    publish_frame_rgba(0, 8, 1, vec![0u8; 32]);
    publish_frame_rgba(8, 8, 1, vec![0u8; 8 * 8 * 4 - 1]);
    publish_frame_rgba(8, 8, 1, vec![0u8; 8 * 8 * 4 + 1]);
    publish_frame_rgba(u32::MAX, u32::MAX, 1, vec![0u8; 16]);
    let ctx = digest_context(&server, automation_scopes_capture(), "np", 1_000);
    let outcome = handle_envelope(&digest_envelope(2, &params), &dispatcher, &ctx);
    assert!(
        response_text(&outcome).contains("Unavailable"),
        "bad publishes must not become digestable: {}",
        response_text(&outcome)
    );
    // A valid publish after bad ones still verifies (drop, not poison).
    publish_frame_rgba(8, 8, 2, fixture_rgba(8, 8, 1));
    let ctx = digest_context(&server, automation_scopes_capture(), "np", 2_000);
    let outcome = handle_envelope(&digest_envelope(3, &params), &dispatcher, &ctx);
    assert!(!outcome.was_error, "valid publish must verify");
    assert!(
        response_text(&outcome).contains("\"frameSeq\":2"),
        "got: {}",
        response_text(&outcome)
    );
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn frame_hash_audit_covers_granted_and_denied_and_stays_bounded() {
    use crate::frame_digest::frame_digest_hex;
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let rgba = fixture_rgba(8, 8, 4);
    publish_frame_rgba(8, 8, 55, rgba.clone());
    let tok =
        issue_automation_bearer_with_ttl("au", "t:1", AutomationFamily::FrameDigest, 0, 120_000)
            .unwrap();
    // Granted call appends a digest entry carrying the served digest.
    let before = frame_audit_len_for_tests();
    let ctx = digest_context(&server, automation_scopes_capture(), "au", 0);
    let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\"}}");
    let outcome = handle_envelope(&digest_envelope(1, &params), &dispatcher, &ctx);
    assert!(!outcome.was_error);
    let text = response_text(&outcome);
    let served = frame_digest_hex(8, 8, 55, &rgba);
    assert!(text.contains(&served));
    assert_eq!(frame_audit_len_for_tests(), before + 1);
    let snap = frame_audit_snapshot_for_tests();
    let entry = snap.last().unwrap();
    assert_eq!(entry.format, "digest");
    assert_eq!(entry.session_id, "au");
    assert_eq!(entry.terminal_id, "t:1");
    assert_eq!(entry.frame_seq, 55);
    assert_eq!(entry.digest_hex, served);
    // Denied calls append too (attributable terminal): wrong-terminal
    // denials are unbounded by rate (auth fails first), so 65 of them
    // prove the 64-entry drop-oldest bound deterministically.
    for id in 2..=66u64 {
        let bad = format!("{{\"terminalId\":\"t:9\",\"bearer\":\"{tok}\"}}");
        let outcome = handle_envelope(&digest_envelope(id, &bad), &dispatcher, &ctx);
        assert!(outcome.was_error);
    }
    assert_eq!(frame_audit_len_for_tests(), MAX_AUTOMATION_BEARERS);
    let snap = frame_audit_snapshot_for_tests();
    assert!(snap.iter().all(|e| e.format == "digest"));
    assert!(
        snap.iter().all(|e| e.digest_hex.is_empty()),
        "denied entries carry no digest"
    );
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn frame_hash_family_isolation_holds_in_both_directions() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    publish_frame_rgba(8, 8, 1, fixture_rgba(8, 8, 6));
    publish_grid_text(vec!["ok".to_string()], 0, 0, true, 1, 80, 24);
    let digest_tok =
        issue_automation_bearer_with_ttl("iso", "t:1", AutomationFamily::FrameDigest, 0, 60_000)
            .unwrap();
    let capture_tok = issue_automation_bearer("iso", "t:1", AutomationFamily::Capture, 0).unwrap();
    let ctx = digest_context(&server, automation_scopes_capture(), "iso", 0);
    // Capture bearer on frameHash: denied (never widened).
    let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{capture_tok}\"}}");
    let outcome = handle_envelope(&digest_envelope(1, &params), &dispatcher, &ctx);
    assert!(response_text(&outcome).contains("ScopeDenied"));
    // Digest bearer on captureFrame: denied (never widened).
    let params =
        format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{digest_tok}\",\"format\":\"semantic\"}}");
    let outcome = handle_envelope(&capture_envelope(2, &params), &dispatcher, &ctx);
    assert!(
        response_text(&outcome).contains("ScopeDenied"),
        "digest bearer must not capture: {}",
        response_text(&outcome)
    );
    // Digest bearer on frameHash: verifies (control case).
    let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{digest_tok}\"}}");
    let outcome = handle_envelope(&digest_envelope(3, &params), &dispatcher, &ctx);
    assert!(!outcome.was_error);
    // No-bypass: even every scope granted, a forged digest token denies,
    // and revocation takes effect immediately.
    let all = digest_context(&server, crate::scope::ScopeSet::all(), "iso", 0);
    let params = r#"{"terminalId":"t:1","bearer":"forged-digest-token"}"#;
    let outcome = handle_envelope(&digest_envelope(4, params), &dispatcher, &all);
    assert!(response_text(&outcome).contains("ScopeDenied"));
    assert!(revoke_automation_bearer(&digest_tok));
    let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{digest_tok}\"}}");
    let outcome = handle_envelope(&digest_envelope(5, &params), &dispatcher, &ctx);
    assert!(response_text(&outcome).contains("ScopeDenied"));
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn frame_digest_publish_gate_arms_only_with_live_grant() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    assert!(!frame_digest_publish_wanted());
    let synth = issue_automation_bearer("gate", "t:1", AutomationFamily::Synthesize, 0).unwrap();
    let cap = issue_automation_bearer("gate", "t:1", AutomationFamily::Capture, 0).unwrap();
    // Other families never arm the RGBA publish path.
    assert!(!frame_digest_publish_wanted());
    let digest =
        issue_automation_bearer_with_ttl("gate", "t:1", AutomationFamily::FrameDigest, 0, 60_000)
            .unwrap();
    assert!(frame_digest_publish_wanted());
    assert!(revoke_automation_bearer(&digest));
    assert!(!frame_digest_publish_wanted());
    assert!(revoke_automation_bearer(&synth));
    assert!(revoke_automation_bearer(&cap));
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn automation_unscoped_synthesize_is_scope_denied_no_partial_state() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let seq_before = synthetic_seq_for_tests();
    // Empty scopes + no bearer: fail fast ScopeDenied.
    let ctx = automation_context(&server, crate::scope::ScopeSet::new(), "s1", 1000);
    let outcome = handle_envelope(
        &synth_envelope(
            1,
            r#"{"terminalId":"t:1","bearer":"nope","originLabel":"harness","events":[{"type":"key","key":"a"}]}"#,
        ),
        &dispatcher,
        &ctx,
    );
    assert!(outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("ScopeDenied"), "got: {text}");
    assert_eq!(synthetic_seq_for_tests(), seq_before);
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn automation_bearer_matrix_fails_closed() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let synth_scopes = automation_scopes_synthesize();
    let capture_scopes = automation_scopes_capture();
    // Issue valid bearers at t=1000.
    let synth_tok =
        issue_automation_bearer("sess-a", "t:1", AutomationFamily::Synthesize, 1000).unwrap();
    let capture_tok =
        issue_automation_bearer("sess-a", "t:1", AutomationFamily::Capture, 1000).unwrap();
    // Absent bearer.
    let ctx = automation_context(&server, synth_scopes.clone(), "sess-a", 1000);
    let outcome = handle_envelope(
        &synth_envelope(
            1,
            r#"{"terminalId":"t:1","originLabel":"h","events":[{"type":"key","key":"a"}]}"#,
        ),
        &dispatcher,
        &ctx,
    );
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("ScopeDenied")
    );
    assert!(outcome.was_error);
    // Wrong-session bearer.
    let ctx_other = automation_context(&server, synth_scopes.clone(), "sess-b", 1000);
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{synth_tok}\",\"originLabel\":\"h\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    let outcome = handle_envelope(&synth_envelope(2, &params), &dispatcher, &ctx_other);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("ScopeDenied")
    );
    // Wrong-terminal bearer.
    let ctx = automation_context(&server, synth_scopes.clone(), "sess-a", 1000);
    let params = format!(
        "{{\"terminalId\":\"t:2\",\"bearer\":\"{synth_tok}\",\"originLabel\":\"h\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    let outcome = handle_envelope(&synth_envelope(3, &params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("ScopeDenied")
    );
    // Wrong-family bearer (capture token on synthesize).
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{capture_tok}\",\"originLabel\":\"h\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    let outcome = handle_envelope(&synth_envelope(4, &params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("ScopeDenied")
    );
    // Expired bearer.
    let mut ctx_expired = automation_context(&server, synth_scopes.clone(), "sess-a", 1000);
    ctx_expired.uptime_ms = 1000 + AUTOMATION_BEARER_TTL_MS;
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{synth_tok}\",\"originLabel\":\"h\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    let outcome = handle_envelope(&synth_envelope(5, &params), &dispatcher, &ctx_expired);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("ScopeDenied"), "expired must deny: {text}");
    // Capture wrong-family (synthesize token on capture): re-issue a live
    // synthesize token to prove family mismatch distinctly (the earlier
    // synth token was consumed by the expiry check above).
    publish_grid_text(vec!["hello".to_string()], 0, 5, true, 3, 80, 24);
    let ctx_cap = automation_context(&server, capture_scopes, "sess-a", 1000);
    let live_synth =
        issue_automation_bearer("sess-a", "t:1", AutomationFamily::Synthesize, 1000).unwrap();
    let params2 =
        format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{live_synth}\",\"format\":\"semantic\"}}");
    let outcome = handle_envelope(&capture_envelope(6, &params2), &dispatcher, &ctx_cap);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("ScopeDenied")
    );
    let _ = capture_tok;
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn automation_scope_intersection_requires_debug_plus_terminal() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let tok = issue_automation_bearer("s1", "t:1", AutomationFamily::Synthesize, 500).unwrap();
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"originLabel\":\"h\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    // DebugControl alone (missing TerminalInput) denies.
    let mut only_debug = crate::scope::ScopeSet::new();
    only_debug.insert(crate::scope::Scope::DebugControl);
    let ctx = automation_context(&server, only_debug, "s1", 500);
    let outcome = handle_envelope(&synth_envelope(1, &params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("ScopeDenied")
    );
    // TerminalInput alone (missing DebugControl) denies.
    let mut only_term = crate::scope::ScopeSet::new();
    only_term.insert(crate::scope::Scope::TerminalInput);
    let ctx = automation_context(&server, only_term, "s1", 500);
    let outcome = handle_envelope(&synth_envelope(2, &params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("ScopeDenied")
    );
    // Capture: DebugTrace alone denies, TerminalInspect alone denies.
    let cap_tok = issue_automation_bearer("s1", "t:1", AutomationFamily::Capture, 500).unwrap();
    publish_grid_text(vec!["x".to_string()], 0, 1, true, 1, 80, 24);
    let cap_params =
        format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{cap_tok}\",\"format\":\"semantic\"}}");
    let mut only_trace = crate::scope::ScopeSet::new();
    only_trace.insert(crate::scope::Scope::DebugTrace);
    let ctx = automation_context(&server, only_trace, "s1", 500);
    let outcome = handle_envelope(&capture_envelope(3, &cap_params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("ScopeDenied")
    );
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn automation_synthesize_bounds_fail_closed() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let tok = issue_automation_bearer("s1", "t:1", AutomationFamily::Synthesize, 0).unwrap();
    let ctx = automation_context(&server, automation_scopes_synthesize(), "s1", 0);
    // Zero events.
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"originLabel\":\"h\",\"events\":[]}}"
    );
    let outcome = handle_envelope(&synth_envelope(1, &params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("InvalidParams")
    );
    // 65 events exceeds the 64/call ceiling.
    let many: Vec<String> = (0..65)
        .map(|_| "{\"type\":\"key\",\"key\":\"a\"}".to_string())
        .collect();
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"originLabel\":\"h\",\"events\":[{}]}}",
        many.join(",")
    );
    let outcome = handle_envelope(&synth_envelope(2, &params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("InvalidParams")
    );
    // Wildcard terminal fails closed (exactly one t:N per call).
    let params = format!(
        "{{\"terminalId\":\"*\",\"bearer\":\"{tok}\",\"originLabel\":\"h\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    let outcome = handle_envelope(&synth_envelope(3, &params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("InvalidParams")
    );
    // Unknown event type.
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"originLabel\":\"h\",\"events\":[{{\"type\":\"teleport\"}}]}}"
    );
    let outcome = handle_envelope(&synth_envelope(4, &params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("InvalidParams")
    );
    // Bad mouse button.
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"originLabel\":\"h\",\"events\":[{{\"type\":\"mouse\",\"button\":\"Side\",\"action\":\"click\",\"col\":1,\"row\":1}}]}}"
    );
    let outcome = handle_envelope(&synth_envelope(5, &params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("InvalidParams")
    );
    // Zero wheel delta.
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"originLabel\":\"h\",\"events\":[{{\"type\":\"wheel\",\"deltaRows\":0}}]}}"
    );
    let outcome = handle_envelope(&synth_envelope(6, &params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("InvalidParams")
    );
    // Paste with NUL.
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"originLabel\":\"h\",\"events\":[{{\"type\":\"paste\",\"text\":\"a\\u0000b\"}}]}}"
    );
    let outcome = handle_envelope(&synth_envelope(7, &params), &dispatcher, &ctx);
    assert!(outcome.was_error);
    // Missing originLabel.
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    let outcome = handle_envelope(&synth_envelope(8, &params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("InvalidParams")
    );
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn automation_synthesize_success_marks_synthetic_origin() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let tok =
        issue_automation_bearer("harness", "t:1", AutomationFamily::Synthesize, 2000).unwrap();
    let ctx = automation_context(&server, automation_scopes_synthesize(), "harness", 2000);
    let seq_before = synthetic_seq_for_tests();
    let params = format!(
        concat!(
            "{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"originLabel\":\"e2e-harness\",",
            "\"events\":[{{\"type\":\"key\",\"key\":\"Enter\",\"pressed\":true}},",
            "{{\"type\":\"mouse\",\"button\":\"Left\",\"action\":\"click\",\"col\":10,\"row\":5}},",
            "{{\"type\":\"wheel\",\"deltaRows\":-3}},",
            "{{\"type\":\"paste\",\"text\":\"echo hi\"}}]}}"
        ),
        tok = tok
    );
    let outcome = handle_envelope(&synth_envelope(1, &params), &dispatcher, &ctx);
    assert!(!outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("\"accepted\":4"), "got: {text}");
    assert!(text.contains("\"rejected\":0"), "got: {text}");
    assert!(text.contains("\"synthetic\":true"), "got: {text}");
    assert!(synthetic_seq_for_tests() > seq_before);
    // Input-ring observability carries the indelible synthetic marker.
    let ring_ctx = automation_context(
        &server,
        crate::scope::ScopeSet::cli_default(),
        "harness",
        2000,
    );
    let _ = ring_ctx;
    let guard = live_input_store().lock().unwrap();
    assert!(guard.len() >= 4);
    assert!(
        guard
            .iter()
            .all(|e| e.label.contains("[synthetic:e2e-harness]"))
    );
    drop(guard);
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn automation_synthesize_rate_sheds_with_budget_error() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let tok = issue_automation_bearer("s1", "t:1", AutomationFamily::Synthesize, 0).unwrap();
    let ctx = automation_context(&server, automation_scopes_synthesize(), "s1", 0);
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"originLabel\":\"load\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    for id in 1..=MAX_SYNTH_CALLS_PER_SEC as u64 {
        let outcome = handle_envelope(&synth_envelope(id, &params), &dispatcher, &ctx);
        assert!(!outcome.was_error, "call {id} must pass under ceiling");
    }
    let outcome = handle_envelope(
        &synth_envelope(MAX_SYNTH_CALLS_PER_SEC as u64 + 1, &params),
        &dispatcher,
        &ctx,
    );
    assert!(outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("RateLimited"), "got: {text}");
    // A different bearer (benign concurrent session) is unaffected.
    let tok2 = issue_automation_bearer("s2", "t:2", AutomationFamily::Synthesize, 0).unwrap();
    let ctx2 = automation_context(&server, automation_scopes_synthesize(), "s2", 0);
    let params2 = format!(
        "{{\"terminalId\":\"t:2\",\"bearer\":\"{tok2}\",\"originLabel\":\"load\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    let outcome = handle_envelope(&synth_envelope(100, &params2), &dispatcher, &ctx2);
    assert!(!outcome.was_error);
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn automation_capture_semantic_redacts_and_labels_untrusted() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    publish_grid_text(
        vec![
            "$ echo hello".to_string(),
            "hello".to_string(),
            "DB_PASSWORD=hunter2".to_string(),
            "clipboard bytes leak".to_string(),
        ],
        1,
        5,
        true,
        9,
        80,
        24,
    );
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let tok = issue_automation_bearer("s1", "t:1", AutomationFamily::Capture, 7000).unwrap();
    let ctx = automation_context(&server, automation_scopes_capture(), "s1", 7000);
    let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"format\":\"semantic\"}}");
    let outcome = handle_envelope(&capture_envelope(1, &params), &dispatcher, &ctx);
    assert!(!outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("\"snapshot\":\"frame\""), "got: {text}");
    assert!(
        text.contains("\"trust\":\"untrusted-observation\""),
        "got: {text}"
    );
    assert!(text.contains("hello"), "got: {text}");
    assert!(!text.contains("hunter2"), "secret leaked: {text}");
    assert!(
        !text.contains("clipboard bytes leak"),
        "clipboard leaked: {text}"
    );
    assert!(text.contains(REDACTED_MARKER), "got: {text}");
    assert!(text.contains("\"frameSeq\":9"), "got: {text}");
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn automation_capture_pixels_requires_opt_in_masks_and_audits() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    publish_grid_text(vec!["SECRET=topsecret".to_string()], 0, 1, true, 11, 80, 24);
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let tok = issue_automation_bearer("s1", "t:1", AutomationFamily::Capture, 8000).unwrap();
    let ctx = automation_context(&server, automation_scopes_capture(), "s1", 8000);
    // Without explicit opt-in: fail closed.
    let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"format\":\"pixels\"}}");
    let outcome = handle_envelope(&capture_envelope(1, &params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("InvalidParams")
    );
    // With opt-in: masked record, zero text, audited caller.
    let audit_before = frame_audit_len_for_tests();
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"format\":\"pixels\",\"explicitOptIn\":true}}"
    );
    let outcome = handle_envelope(&capture_envelope(2, &params), &dispatcher, &ctx);
    assert!(!outcome.was_error);
    let text = String::from_utf8(outcome.response).unwrap();
    assert!(text.contains("\"format\":\"pixels\""), "got: {text}");
    assert!(text.contains("\"masked\":true"), "got: {text}");
    assert!(text.contains("\"audited\":true"), "got: {text}");
    assert!(text.contains("\"caller\":\"s1\""), "got: {text}");
    assert!(!text.contains("topsecret"), "pixels leaked text: {text}");
    assert!(
        !text.contains("\"lines\""),
        "pixels must carry zero text: {text}"
    );
    assert!(frame_audit_len_for_tests() > audit_before);
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn automation_capture_rate_sheds_at_fps_ceiling() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    publish_grid_text(vec!["f".to_string()], 0, 1, true, 1, 80, 24);
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let tok = issue_automation_bearer("s1", "t:1", AutomationFamily::Capture, 0).unwrap();
    let ctx = automation_context(&server, automation_scopes_capture(), "s1", 0);
    let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"format\":\"semantic\"}}");
    for id in 1..=MAX_CAPTURE_FPS as u64 {
        let outcome = handle_envelope(&capture_envelope(id, &params), &dispatcher, &ctx);
        assert!(!outcome.was_error, "frame {id} must pass under ceiling");
    }
    let outcome = handle_envelope(
        &capture_envelope(MAX_CAPTURE_FPS as u64 + 1, &params),
        &dispatcher,
        &ctx,
    );
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("RateLimited")
    );
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn automation_bearer_lifecycle_revoke_ttl_cap_and_no_env_issuance() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    // TTL bounds hold fail-closed.
    assert!(
        issue_automation_bearer_with_ttl("s", "t:1", AutomationFamily::Synthesize, 0, 0).is_err()
    );
    assert!(
        issue_automation_bearer_with_ttl(
            "s",
            "t:1",
            AutomationFamily::Synthesize,
            0,
            AUTOMATION_BEARER_TTL_MS + 1
        )
        .is_err()
    );
    // Revocation takes effect immediately.
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let tok = issue_automation_bearer("s1", "t:1", AutomationFamily::Synthesize, 0).unwrap();
    assert!(revoke_automation_bearer(&tok));
    let ctx = automation_context(&server, automation_scopes_synthesize(), "s1", 0);
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"originLabel\":\"h\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    let outcome = handle_envelope(&synth_envelope(1, &params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("ScopeDenied")
    );
    // No-bypass: elevation alone never substitutes for a bearer. Even
    // with every scope granted, a forged token still fails closed, and
    // issuance has no env/config/flag path (code inspection: only
    // `issue_automation_bearer` inserts into the memory-only store).
    let ctx = automation_context(&server, crate::scope::ScopeSet::all(), "s1", 0);
    let params = r#"{"terminalId":"t:1","bearer":"forged-token","originLabel":"h","events":[{"type":"key","key":"a"}]}"#;
    let outcome = handle_envelope(&synth_envelope(2, params), &dispatcher, &ctx);
    assert!(
        String::from_utf8(outcome.response)
            .unwrap()
            .contains("ScopeDenied")
    );
    // Bearers are never persisted: the store is memory-only.
    assert_eq!(automation_bearer_count_for_tests(), 0);
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn regranted_scope_does_not_resurrect_old_bearer() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let authority = crate::ctl::ControlAuthority::new();
    let mut scopes = crate::scope::ScopeSet::cli_default();
    scopes.insert(crate::scope::Scope::DebugControl);
    let grant = authority
        .open_connection(
            scopes.clone(),
            crate::ctl::TerminalCapabilities::from_scopes(&scopes),
        )
        .expect("connection grant");
    let session_id = grant.session_id().to_string();
    let context = ServeContext::with_connection_grant_for_tests(&test_server_info(), grant);
    let token = context
        .issue_automation_bearer("t:1", AutomationFamily::Synthesize, 0)
        .expect("bearer");
    assert!(authority.revoke_scope(&session_id, crate::scope::Scope::DebugControl));
    assert!(authority.grant_scope(&session_id, crate::scope::Scope::DebugControl));
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{token}\",\"originLabel\":\"h\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    let outcome = handle_envelope(
        &synth_envelope(1, &params),
        &Dispatcher::with_defaults(),
        &context,
    );
    assert!(outcome.was_error);
    assert!(response_text(&outcome).contains("ScopeDenied"));
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn bearer_is_bound_to_one_connection_and_revoked_on_disconnect() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let authority = crate::ctl::ControlAuthority::new();
    let scopes = crate::scope::ScopeSet::all();
    let capabilities = crate::ctl::TerminalCapabilities::from_scopes(&scopes);
    let grant_a = authority
        .open_connection(scopes.clone(), capabilities.clone())
        .expect("first connection");
    let grant_b = authority
        .open_connection(scopes, capabilities)
        .expect("second connection");
    let context_a = ServeContext::with_connection_grant_for_tests(&test_server_info(), grant_a);
    let context_b = ServeContext::with_connection_grant_for_tests(&test_server_info(), grant_b);
    let token = context_a
        .issue_automation_bearer("t:1", AutomationFamily::Synthesize, 0)
        .expect("bearer");
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{token}\",\"originLabel\":\"h\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    let denied = handle_envelope(
        &synth_envelope(1, &params),
        &Dispatcher::with_defaults(),
        &context_b,
    );
    assert!(denied.was_error);
    assert!(response_text(&denied).contains("ScopeDenied"));
    context_a.close_connection();
    let revoked = handle_envelope(
        &synth_envelope(2, &params),
        &Dispatcher::with_defaults(),
        &context_a,
    );
    assert!(revoked.was_error);
    assert!(response_text(&revoked).contains("Unauthenticated"));
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn automation_bearer_entropy_is_not_metadata_derived() {
    let _guard = lock_introspection_for_test();
    clear_automation_for_tests();
    let first = issue_automation_bearer("entropy", "t:1", AutomationFamily::Synthesize, 7)
        .expect("first bearer");
    let second = issue_automation_bearer("entropy", "t:1", AutomationFamily::Synthesize, 7)
        .expect("second bearer");
    assert_ne!(first, second);
    assert_eq!(first.len(), 32);
    assert_eq!(second.len(), 32);
    clear_automation_for_tests();
}

/// CTX-0792 / #1403: the bearer token is 128 bits of platform
/// CSPRNG output on **every** platform (one `getrandom` path, no cfg split, no
/// hash-derived fallback), so the properties that matter are pinned here rather
/// than assumed: full width, distinct draws, halves that are distinct from each
/// other, and every one of the 128 bit positions taking both values across
/// draws. A constant source, a narrow source, a zeroed half, or a mirrored half
/// fails this. What it cannot prove is CSPRNG quality — that is `getrandom`'s
/// contract, and the point of this test is to fail loudly if anyone reintroduces
/// a weaker source in its place.
#[test]
fn bearer_tokens_are_full_width_csprng_output_on_every_platform() {
    const DRAWS: usize = 64;
    const TOKEN_BYTES: usize = 16;
    const HEX_CHARS: usize = TOKEN_BYTES * 2;

    let _guard = lock_introspection_for_test();
    clear_automation_for_tests();
    let mut tokens = std::collections::BTreeSet::new();
    // Each half is tracked separately: a source that fills only 64 bits and
    // mirrors them would still vary every bit position and stay distinct, so
    // half-distinctness is what actually pins the full 128-bit width.
    let mut low_halves = std::collections::BTreeSet::new();
    let mut high_halves = std::collections::BTreeSet::new();
    let mut saw_one = [false; TOKEN_BYTES * 8];
    let mut saw_zero = [false; TOKEN_BYTES * 8];
    for _ in 0..DRAWS {
        let token = issue_automation_bearer("csprng", "t:1", AutomationFamily::Synthesize, 7)
            .expect("bearer");
        assert_eq!(
            token.len(),
            HEX_CHARS,
            "a bearer must carry the full 128-bit token width"
        );
        assert!(
            token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "token must stay the pinned lowercase hex shape (length {})",
            token.len()
        );
        let bytes: Vec<u8> = (0..TOKEN_BYTES)
            .map(|i| u8::from_str_radix(&token[i * 2..i * 2 + 2], 16).expect("hex pair"))
            .collect();
        for (byte_index, byte) in bytes.iter().enumerate() {
            for bit in 0..8 {
                let position = byte_index * 8 + bit;
                if byte & (1 << bit) == 0 {
                    saw_zero[position] = true;
                } else {
                    saw_one[position] = true;
                }
            }
        }
        let (low, high) = bytes.split_at(TOKEN_BYTES / 2);
        assert_ne!(
            low, high,
            "the high half must carry its own bytes, not a copy of the low half"
        );
        low_halves.insert(low.to_vec());
        high_halves.insert(high.to_vec());
        assert!(tokens.insert(token), "every draw must be distinct");
    }
    for position in 0..TOKEN_BYTES * 8 {
        assert!(
            saw_one[position] && saw_zero[position],
            "token bit {position} never varied across {DRAWS} CSPRNG draws"
        );
    }
    assert_eq!(
        low_halves.len(),
        DRAWS,
        "the low 64 bits must be unpredictable on their own"
    );
    assert_eq!(
        high_halves.len(),
        DRAWS,
        "the high 64 bits must be unpredictable on their own, not a copy of the low half"
    );
    clear_automation_for_tests();
}

/// CTX-0792 / #1403: issuing a bearer binds the bearer, not the connection.
/// The bearer is limited to its terminal and family by its own record; the
/// connection's terminal capabilities are unchanged, so a harness that binds
/// a capture bearer to `t:1` can still verify its own input on `t:1`.
#[test]
fn automation_bearer_issuance_leaves_connection_capabilities_untouched() {
    let _guard = lock_introspection_for_test();
    clear_automation_for_tests();
    let authority = crate::ctl::ControlAuthority::new();
    let scopes = crate::scope::ScopeSet::all();
    let grant = authority
        .open_connection(
            scopes.clone(),
            crate::ctl::TerminalCapabilities::from_scopes(&scopes),
        )
        .expect("connection grant");
    let before = grant.snapshot().expect("snapshot");
    let input = crate::ctl::params_send_input("t:1", "x");
    let text = crate::ctl::params_terminal_id("t:1");

    let token = crate::devtools::automation::issue_automation_bearer_for_connection(
        &grant,
        "t:1",
        AutomationFamily::Capture,
        0,
        None,
    )
    .expect("capture bearer");
    assert_eq!(
        grant.snapshot().expect("snapshot"),
        before,
        "issuance changes neither scopes, map, nor consent generation"
    );
    assert!(
        grant
            .authorize(crate::ctl::METHOD_SEND_INPUT, Some(&input))
            .is_ok()
    );
    assert!(
        grant
            .authorize(crate::ctl::METHOD_GET_TERMINAL_TEXT, Some(&text))
            .is_ok()
    );
    assert!(crate::devtools::automation::revoke_automation_bearer(
        &token
    ));
    assert_eq!(grant.snapshot().expect("snapshot"), before);
    clear_automation_for_tests();
}

/// A session that cannot drive a terminal never gains the capability to bind
/// one: issuance is refused and no bearer is minted, so no automation token
/// survives a denied capability.
#[test]
fn denied_terminal_capability_mints_no_bearer() {
    let _guard = lock_introspection_for_test();
    clear_automation_for_tests();
    let authority = crate::ctl::ControlAuthority::new();
    let mut scopes = crate::scope::ScopeSet::cli_default();
    scopes.insert(crate::scope::Scope::DebugControl);
    let grant = authority
        .open_connection(
            scopes.clone(),
            crate::ctl::TerminalCapabilities::from_scopes(&scopes),
        )
        .expect("connection grant");
    let session_id = grant.session_id().to_string();
    // Consent is withdrawn between the capability decision and the binding.
    assert!(authority.revoke_scope(&session_id, crate::scope::Scope::TerminalInput));
    assert!(
        crate::devtools::automation::issue_automation_bearer_for_connection(
            &grant,
            "t:1",
            AutomationFamily::Synthesize,
            0,
            None,
        )
        .is_err()
    );
    assert_eq!(
        crate::devtools::automation::automation_bearer_count_for_tests(),
        0,
        "a denied capability must not leave a bearer behind"
    );
    clear_automation_for_tests();
}

#[test]
fn automation_params_two_tier_envelope_bound() {
    // Automation methods admit larger params than the 4 KiB
    // introspection bound (up to 32 KiB); other methods stay capped.
    let big_pad = "p".repeat(MAX_PARAMS_BYTES);
    let auto_payload = format!(
        "{{\"id\":1,\"method\":\"{METHOD_SYNTHESIZE_INPUT}\",\"version\":\"1.0\",\"params\":{{\"pad\":\"{big_pad}\"}}}}"
    );
    assert!(parse_request(auto_payload.as_bytes()).is_ok());
    let plain_payload = format!(
        "{{\"id\":1,\"method\":\"bitty.debug/getGridText\",\"version\":\"1.0\",\"params\":{{\"pad\":\"{big_pad}\"}}}}"
    );
    assert!(parse_request(plain_payload.as_bytes()).is_err());
}

// ── CTX-0539: post-connect endpoint binding ─────────────────────────────

/// The endpoint identity captured before connect must match the connected
/// stream's kernel-reported peer, and a swapped endpoint must be rejected.
#[cfg(unix)]
#[test]
fn connected_endpoint_binds_to_vetted_inode_and_rejects_swap() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let base = std::env::temp_dir().join(format!("bitty-ctx0539-{}-ipc", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = base.join("s.sock");
    let socket_str = socket_path.to_str().unwrap().to_string();
    let uid = std::fs::symlink_metadata(&base).unwrap().uid();

    // Legitimate endpoint.
    let legit = std::os::unix::net::UnixListener::bind(&socket_str).unwrap();
    std::fs::set_permissions(&socket_str, std::fs::Permissions::from_mode(0o600)).unwrap();
    let expected = verify_socket_endpoint_for_connect(&socket_str, uid).unwrap();

    // Happy path: a client connected to the vetted endpoint verifies.
    let client = std::os::unix::net::UnixStream::connect(&socket_str).unwrap();
    let (_accepted, _) = legit.accept().unwrap();
    assert!(verify_connected_endpoint(&client, expected).is_ok());
    // Tampering with the expectation is rejected.
    let mut wrong = expected;
    wrong.ino = expected.ino.wrapping_add(1);
    assert!(matches!(
        verify_connected_endpoint(&client, wrong),
        Err(IpcError::Unauthenticated { .. })
    ));
    drop(client);

    // Checked-then-swapped: replace the endpoint at the same path.
    drop(legit);
    std::fs::remove_file(&socket_str).unwrap();
    let spoof = std::os::unix::net::UnixListener::bind(&socket_str).unwrap();
    std::fs::set_permissions(&socket_str, std::fs::Permissions::from_mode(0o600)).unwrap();
    let swapped = std::os::unix::net::UnixStream::connect(&socket_str).unwrap();
    let (_spoof_accepted, _) = spoof.accept().unwrap();
    assert!(matches!(
        verify_connected_endpoint(&swapped, expected),
        Err(IpcError::Unauthenticated { .. })
    ));

    drop(spoof);
    std::fs::remove_dir_all(&base).ok();
}

/// A pair stream has no filesystem peer and must fail closed.
#[cfg(unix)]
#[test]
fn connected_endpoint_rejects_unnamed_peer() {
    let (client, _server) = std::os::unix::net::UnixStream::pair().unwrap();
    let identity = SocketEndpointIdentity {
        dev: 0,
        ino: 0,
        uid: 0,
        mode: 0o600,
    };
    assert!(matches!(
        verify_connected_endpoint(&client, identity),
        Err(IpcError::Unauthenticated { .. })
    ));
}

// ── trace lifecycle (DT-03, #1099) ─────────────────────────────────────────
//
// `startTrace` / `stopTrace` / `fetchTraceChunk` over the dispatcher:
// scope matrix, bounds, redaction, 256 KiB pagination with byte-accurate
// previews, and the `0600` spool export. All content is synthetic fixture
// text — never secrets (P0-AC-026 harness rule).

/// Serial guard for the process-global trace and record stores (same
/// `OnceLock<Mutex<()>>` idiom as the introspection lock; std-only).
fn trace_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_trace_for_test() -> std::sync::MutexGuard<'static, ()> {
    trace_test_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn trace_scopes() -> crate::scope::ScopeSet {
    let mut set = crate::scope::ScopeSet::new();
    set.insert(crate::scope::Scope::DebugTrace);
    set
}

fn trace_context(server: &ServerInfo, now_ms: u64) -> ServeContext {
    let mut ctx =
        ServeContext::with_granted_session_for_tests(server, trace_scopes(), "trace-test");
    ctx.uptime_ms = now_ms;
    ctx
}

fn trace_envelope(id: u64, method: &str, params: &str) -> Vec<u8> {
    format!("{{\"id\":{id},\"method\":\"{method}\",\"version\":\"1.0\",\"params\":{params}}}")
        .into_bytes()
}

/// Extract a `"key":"value"` string field from a response (no unescape).
fn response_field(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let at = text.find(needle.as_str())?;
    let rest = &text[at + needle.len()..];
    let mut out = String::new();
    let mut chars = rest.chars();
    loop {
        match chars.next()? {
            '"' => return Some(out),
            '\\' => {
                let e = chars.next()?;
                out.push('\\');
                out.push(e);
            }
            c => out.push(c),
        }
    }
}

/// Unescape a JSON string body (responses from these tests only carry
/// `\"`, `\\`, `\n`, `\r`, `\t`, `\uXXXX` escapes plus raw UTF-8).
fn unescape_json_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                let code = u32::from_str_radix(&hex, 16).unwrap_or(0xFFFD);
                out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
            }
            Some(e) => {
                out.push('\\');
                out.push(e);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn unique_spool_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("bitty-trace-test-{}-{tag}", std::process::id()))
}

#[test]
fn trace_lifecycle_start_stop_fetch_roundtrip() {
    let _guard = lock_trace_for_test();
    clear_traces_for_tests();
    clear_recordings_for_tests();
    let spool = unique_spool_dir("roundtrip");
    std::fs::remove_dir_all(&spool).ok();
    set_trace_spool_dir_for_tests(spool.to_string_lossy().as_ref());
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    assert!(dispatcher.contains(METHOD_START_TRACE));
    assert!(dispatcher.contains(METHOD_STOP_TRACE));
    assert!(dispatcher.contains(METHOD_FETCH_TRACE_CHUNK));

    let ctx = trace_context(&server, 1_000);
    let outcome = handle_envelope(
        &trace_envelope(1, METHOD_START_TRACE, "{}"),
        &dispatcher,
        &ctx,
    );
    let text = response_text(&outcome);
    assert!(!outcome.was_error, "startTrace must succeed: {text}");
    assert!(text.contains("\"traceId\":\"trace-1\""), "got: {text}");
    assert!(text.contains("\"chunkBytes\":262144"), "got: {text}");
    assert!(text.contains("trace-1.jsonl"), "got: {text}");

    // Append three instrumentation events through the harness hook.
    let seq0 = append_trace_event(
        "trace-1",
        "panel-1",
        "bitty.panel:mounted",
        "{\"count\":1}",
        7,
        1_001,
    )
    .expect("append must succeed")
    .expect("event must be retained");
    assert_eq!(seq0, 0);
    append_trace_event("trace-1", "panel-1", "lifecycle", "mounted", 7, 1_002).unwrap();
    append_trace_event("trace-1", "queue", "budget", "{\"depth\":3}", 8, 1_003).unwrap();

    // Fetch page 0: small export, no continuation, byte-accurate preview.
    let outcome = handle_envelope(
        &trace_envelope(
            2,
            METHOD_FETCH_TRACE_CHUNK,
            "{\"traceId\":\"trace-1\",\"offset\":0}",
        ),
        &dispatcher,
        &ctx,
    );
    let text = response_text(&outcome);
    assert!(!outcome.was_error, "fetch must succeed: {text}");
    assert!(text.contains("\"continuation\":false"), "got: {text}");
    let raw_chunk = response_field(&text, "chunk").expect("chunk field");
    let chunk = unescape_json_string(&raw_chunk);
    assert!(chunk.contains("\"kind\":\"lifecycle\""), "got: {chunk}");
    assert!(chunk.contains("\"seq\":2"), "got: {chunk}");
    let raw_preview = response_field(&text, "preview").expect("preview field");
    let preview = unescape_json_string(&raw_preview);
    let mut end = chunk.len().min(TRACE_PREVIEW_BYTES);
    while end > 0 && !chunk.is_char_boundary(end) {
        end -= 1;
    }
    assert_eq!(
        preview,
        redact_trace_preview(&chunk[..end]),
        "preview must equal the redacted export prefix byte-for-byte"
    );

    // Stop: spool export, counts, previews, then the record is gone.
    let outcome = handle_envelope(
        &trace_envelope(3, METHOD_STOP_TRACE, "{\"traceId\":\"trace-1\"}"),
        &dispatcher,
        &ctx,
    );
    let text = response_text(&outcome);
    assert!(!outcome.was_error, "stopTrace must succeed: {text}");
    assert!(text.contains("\"spoolMode\":\"0600\""), "got: {text}");
    assert!(text.contains("\"truncated\":false"), "got: {text}");
    assert!(text.contains("\"dropCount\":0"), "got: {text}");
    let spool_file = spool.join("trace-1.jsonl");
    let spooled = std::fs::read(&spool_file).expect("spool file must exist");
    assert_eq!(
        spooled,
        chunk.as_bytes(),
        "spool export must equal the served bytes byte-for-byte"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&spool_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "spool files keep mode 0600");
    }

    // Sibling parity: stop deletes the record; fetch-after-stop is NotFound.
    let outcome = handle_envelope(
        &trace_envelope(4, METHOD_STOP_TRACE, "{\"traceId\":\"trace-1\"}"),
        &dispatcher,
        &ctx,
    );
    assert!(response_text(&outcome).contains("\"code\":\"NotFound\""));
    let outcome = handle_envelope(
        &trace_envelope(
            5,
            METHOD_FETCH_TRACE_CHUNK,
            "{\"traceId\":\"trace-1\",\"offset\":0}",
        ),
        &dispatcher,
        &ctx,
    );
    assert!(response_text(&outcome).contains("\"code\":\"NotFound\""));

    std::fs::remove_dir_all(&spool).ok();
    clear_traces_for_tests();
}

#[test]
fn trace_scope_matrix_denies_inspect_and_unscoped() {
    let _guard = lock_trace_for_test();
    clear_traces_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let methods = [
        (METHOD_START_TRACE, "{}"),
        (METHOD_STOP_TRACE, "{\"traceId\":\"trace-9\"}"),
        (
            METHOD_FETCH_TRACE_CHUNK,
            "{\"traceId\":\"trace-9\",\"offset\":0}",
        ),
    ];
    // `debug.inspect` alone and no debug scope at all: every method denies
    // with `scope`/`ScopeDenied` and creates zero partial state.
    for (label, granted) in [
        ("inspect-only", {
            let mut set = crate::scope::ScopeSet::new();
            set.insert(crate::scope::Scope::DebugInspect);
            set
        }),
        ("unscoped", crate::scope::ScopeSet::new()),
    ] {
        let ctx = ServeContext::with_granted_session_for_tests(&server, granted, "trace-test");
        for (method, params) in methods {
            let outcome = handle_envelope(&trace_envelope(1, method, params), &dispatcher, &ctx);
            let text = response_text(&outcome);
            assert!(
                text.contains("\"code\":\"ScopeDenied\""),
                "{label} {method} must be ScopeDenied: {text}"
            );
        }
    }
    assert_eq!(trace_count_for_tests(), 0);
    // `debug.control` is wider than `debug.trace`: start succeeds.
    let mut control = crate::scope::ScopeSet::new();
    control.insert(crate::scope::Scope::DebugControl);
    let ctx = ServeContext::with_granted_session_for_tests(&server, control, "trace-test");
    let outcome = handle_envelope(
        &trace_envelope(2, METHOD_START_TRACE, "{}"),
        &dispatcher,
        &ctx,
    );
    assert!(!outcome.was_error, "control scope starts traces");
    clear_traces_for_tests();
}

#[test]
fn trace_params_and_budget_fail_closed() {
    let _guard = lock_trace_for_test();
    clear_traces_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let ctx = trace_context(&server, 5_000);
    for (label, params) in [
        ("zero-duration", "{\"durationMs\":0}"),
        ("over-duration", "{\"durationMs\":300001}"),
        ("zero-bytes", "{\"maxBytes\":0}"),
        ("over-bytes", "{\"maxBytes\":4194305}"),
        ("non-object", "[1]"),
    ] {
        let outcome = handle_envelope(
            &trace_envelope(1, METHOD_START_TRACE, params),
            &dispatcher,
            &ctx,
        );
        let text = response_text(&outcome);
        assert!(
            text.contains("\"code\":\"InvalidParams\""),
            "{label} must be InvalidParams: {text}"
        );
    }
    // Four concurrent traces, then the fifth is shed with TooManyTraces.
    for id in 1..=4u64 {
        let outcome = handle_envelope(
            &trace_envelope(id, METHOD_START_TRACE, "{}"),
            &dispatcher,
            &ctx,
        );
        assert!(!outcome.was_error, "trace {id} must start");
    }
    let outcome = handle_envelope(
        &trace_envelope(9, METHOD_START_TRACE, "{}"),
        &dispatcher,
        &ctx,
    );
    let text = response_text(&outcome);
    assert!(text.contains("\"code\":\"TooManyTraces\""), "got: {text}");

    // Unknown ids, over-range offsets, and malformed ids fail closed.
    for (label, method, params, code) in [
        (
            "unknown-stop",
            METHOD_STOP_TRACE,
            "{\"traceId\":\"trace-99\"}",
            "NotFound",
        ),
        (
            "unknown-fetch",
            METHOD_FETCH_TRACE_CHUNK,
            "{\"traceId\":\"trace-99\",\"offset\":0}",
            "NotFound",
        ),
        (
            "over-offset",
            METHOD_FETCH_TRACE_CHUNK,
            "{\"traceId\":\"trace-1\",\"offset\":999999}",
            "InvalidParams",
        ),
        (
            "missing-offset",
            METHOD_FETCH_TRACE_CHUNK,
            "{\"traceId\":\"trace-1\"}",
            "InvalidParams",
        ),
        (
            "wild-id",
            METHOD_STOP_TRACE,
            "{\"traceId\":\"trace-*\"}",
            "InvalidParams",
        ),
    ] {
        let outcome = handle_envelope(&trace_envelope(10, method, params), &dispatcher, &ctx);
        let text = response_text(&outcome);
        assert!(
            text.contains(&format!("\"code\":\"{code}\"")),
            "{label} must be {code}: {text}"
        );
    }

    // Mid-character offsets are rejected (UTF-8 scalar boundaries only).
    append_trace_event("trace-1", "panel-1", "note", "caf\u{e9} latte", 1, 5_001).unwrap();
    let bytes: u64 = {
        let outcome = handle_envelope(
            &trace_envelope(
                11,
                METHOD_FETCH_TRACE_CHUNK,
                "{\"traceId\":\"trace-1\",\"offset\":0}",
            ),
            &dispatcher,
            &ctx,
        );
        let raw = response_field(&response_text(&outcome), "chunk").unwrap();
        unescape_json_string(&raw).len() as u64
    };
    let _ = bytes;
    // Find a mid-character offset inside the retained export: the payload
    // above carries a 2-byte `é`; probe every offset until the handler
    // rejects one (proves the boundary check fires on real content).
    let mut saw_boundary_rejection = false;
    for probe in 0..4096u64 {
        let params = format!("{{\"traceId\":\"trace-1\",\"offset\":{probe}}}");
        let outcome = handle_envelope(
            &trace_envelope(12, METHOD_FETCH_TRACE_CHUNK, &params),
            &dispatcher,
            &ctx,
        );
        let text = response_text(&outcome);
        if text.contains("UTF-8 scalar boundary") {
            saw_boundary_rejection = true;
            break;
        }
        if probe > 2048 && text.contains("\"continuation\":false") {
            break;
        }
    }
    assert!(
        saw_boundary_rejection,
        "mid-character offsets must be rejected"
    );
    clear_traces_for_tests();
}

#[test]
fn trace_redaction_and_input_gating() {
    let _guard = lock_trace_for_test();
    clear_traces_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let ctx = trace_context(&server, 7_000);

    // Default trace: input markers drop with a counted drop; secrets redact.
    let outcome = handle_envelope(
        &trace_envelope(1, METHOD_START_TRACE, "{}"),
        &dispatcher,
        &ctx,
    );
    assert!(!outcome.was_error);
    assert!(
        append_trace_event("trace-1", "harness", "input.key", "a", 1, 7_001)
            .unwrap()
            .is_none(),
        "input markers need includeInput"
    );
    append_trace_event(
        "trace-1",
        "panel-1",
        "snapshot",
        "token abc123 leaked",
        1,
        7_002,
    )
    .unwrap();
    let outcome = handle_envelope(
        &trace_envelope(
            2,
            METHOD_FETCH_TRACE_CHUNK,
            "{\"traceId\":\"trace-1\",\"offset\":0}",
        ),
        &dispatcher,
        &ctx,
    );
    let raw = response_field(&response_text(&outcome), "chunk").unwrap();
    let chunk = unescape_json_string(&raw);
    assert!(
        !chunk.contains("input.key"),
        "marker must not be retained: {chunk}"
    );
    assert!(
        chunk.contains("[redacted]"),
        "secret payload must redact: {chunk}"
    );
    assert!(
        !chunk.contains("token abc123"),
        "secret must not leak: {chunk}"
    );
    let outcome = handle_envelope(
        &trace_envelope(3, METHOD_STOP_TRACE, "{\"traceId\":\"trace-1\"}"),
        &dispatcher,
        &ctx,
    );
    let text = response_text(&outcome);
    assert!(text.contains("\"dropCount\":1"), "got: {text}");
    assert!(text.contains("\"truncated\":true"), "got: {text}");

    // Opted-in trace retains input markers with their synthetic nature
    // visible in the kind (harness/user distinguishable on replay).
    let outcome = handle_envelope(
        &trace_envelope(4, METHOD_START_TRACE, "{\"includeInput\":true}"),
        &dispatcher,
        &ctx,
    );
    assert!(!outcome.was_error);
    let kept = append_trace_event("trace-2", "harness", "input.key", "a", 1, 7_003).unwrap();
    assert_eq!(kept, Some(0));
    // Over-budget lines drop with a counted drop; retained state unchanged.
    let outcome = handle_envelope(
        &trace_envelope(5, METHOD_START_TRACE, "{\"maxBytes\":64}"),
        &dispatcher,
        &ctx,
    );
    assert!(!outcome.was_error);
    let before = trace_count_for_tests();
    assert_eq!(before, 2);
    let dropped = append_trace_event("trace-3", "o", "k", &"x".repeat(200), 1, 7_004).unwrap();
    assert!(dropped.is_none(), "over-budget line must drop");
    let outcome = handle_envelope(
        &trace_envelope(6, METHOD_STOP_TRACE, "{\"traceId\":\"trace-3\"}"),
        &dispatcher,
        &ctx,
    );
    let text = response_text(&outcome);
    assert!(text.contains("\"byteCount\":0"), "got: {text}");
    assert!(text.contains("\"dropCount\":1"), "got: {text}");
    clear_traces_for_tests();
}

// ── record/replay staged v1 (DT-08, #1104) ─────────────────────────────────
//
// Library-only hooks: disabled by default, opt-in retention with
// redaction, headless-harness replay with determinism digests, and no
// plugin re-execution by construction (this module depends on `std`
// only and replays through a caller-supplied driver closure).

#[test]
fn record_hooks_are_disabled_by_default() {
    let _guard = lock_trace_for_test();
    clear_recordings_for_tests();
    assert!(!is_recording_opt_in());
    assert_eq!(
        start_recording("harness", false),
        Err(RecordError::NotOptedIn)
    );
    assert_eq!(record_action("rec-1", "noop"), Err(RecordError::NotOptedIn));
    assert_eq!(stop_recording("rec-1"), Err(RecordError::NotOptedIn));
}

#[test]
fn record_roundtrip_redacts_and_gates_input() {
    let _guard = lock_trace_for_test();
    clear_recordings_for_tests();
    set_recording_opt_in(true);
    let id = start_recording("harness", false).expect("opted-in start");
    assert_eq!(recording_count_for_tests(), 1);

    assert_eq!(record_parser_input(&id, b"hello"), Ok(true));
    assert_eq!(record_action(&id, "pane-mounted"), Ok(true));
    assert_eq!(record_lifecycle(&id, "attached"), Ok(true));
    assert_eq!(
        record_config_diagnostic(&id, "theme resolved: dark"),
        Ok(true)
    );
    // Input markers need per-recording opt-in: counted drop, Ok(false).
    assert_eq!(record_input_marker(&id, "key:a"), Ok(false));
    // Secret-shaped details redact before retention.
    assert_eq!(record_action(&id, "deploy token abc"), Ok(true));

    let recording = stop_recording(&id).expect("stop");
    assert_eq!(recording.owner, "harness");
    assert_eq!(recording.entries.len(), 5);
    assert_eq!(recording.drops, 1);
    assert!(!recording.include_input);
    assert_eq!(recording.entries[0].kind, RecordKind::ParserInput);
    assert_eq!(recording.entries[0].detail, "68656c6c6f");
    assert!(
        recording.entries[0].synthetic,
        "parser inputs are harness-origin"
    );
    assert!(
        !recording.entries[1].synthetic,
        "passive actions stay passive"
    );
    assert_eq!(recording.entries[4].detail, "[redacted]");
    assert!(
        recording.bytes > 0,
        "retained bytes must be accounted, got {}",
        recording.bytes
    );
    // Replay runs through the caller's driver: entries arrive in order,
    // and the same decisions always digest identically.
    let mut seen: Vec<String> = Vec::new();
    let report = replay_recording(&recording, |entry| {
        seen.push(entry.detail.clone());
        ReplayVerdict::Applied
    });
    assert_eq!(report.applied, 5);
    assert_eq!(report.skipped, 0);
    assert_eq!(seen.len(), 5);
    let again = replay_recording(&recording, |_| ReplayVerdict::Applied);
    assert_eq!(
        report.digest_hex, again.digest_hex,
        "replay must be deterministic"
    );
    let skip_all = replay_recording(&recording, |_| ReplayVerdict::Skipped);
    assert_eq!(skip_all.applied, 0);
    assert_eq!(skip_all.skipped, 5);
    assert_ne!(
        skip_all.digest_hex, report.digest_hex,
        "different driver decisions must digest differently"
    );
    clear_recordings_for_tests();
}

#[test]
fn record_input_opt_in_and_bounds_fail_closed() {
    let _guard = lock_trace_for_test();
    clear_recordings_for_tests();
    set_recording_opt_in(true);
    let id = start_recording("harness", true).expect("opted-in start");
    assert_eq!(record_input_marker(&id, "key:a"), Ok(true));
    let recording = stop_recording(&id).expect("stop");
    assert!(recording.include_input);
    assert!(recording.entries[0].synthetic);

    // Unknown ids, bad shapes, and capacity fail closed with no partial state.
    assert_eq!(stop_recording("rec-99"), Err(RecordError::NotFound));
    assert_eq!(record_action("rec-99", "noop"), Err(RecordError::NotFound));
    assert!(matches!(
        record_action(&id, ""),
        Err(RecordError::InvalidDetail(_))
    ));
    assert!(matches!(
        record_parser_input(&id, &[0u8; 4097]),
        Err(RecordError::InvalidDetail(_))
    ));
    let ids: Vec<String> = (0..MAX_ACTIVE_RECORDINGS)
        .map(|_| start_recording("h", false).expect("slot"))
        .collect();
    assert_eq!(start_recording("h", false), Err(RecordError::TooMany));
    for live in &ids {
        stop_recording(live).unwrap();
    }
    clear_recordings_for_tests();
}

// ── DT-04 admission: no-bypass issuance audit (Amendment A1) ─────────────
//
// Acceptance item A1.5: no flag, variable, configuration key, or debug
// build switch issues, persists, or widens an automation bearer. The only
// issuance path is the explicit server-side consent minter
// (`issue_automation_bearer*`): machine-checked here from the wire side —
// no IPC method mints bearers, and even maximally elevated scopes never
// substitute for a bearer.
//
// (Restored: first added under CTX-0660 for #1100, then lost when the
// trace/record rewrite reworked this file.)

// Candidate issuance method names a bypass would hide behind. Every one
// must answer `UnknownMethod` (registration-deny, never scope-deny).
const BYPASS_ISSUANCE_METHODS: &[&str] = &[
    "bitty.debug/issueAutomationBearer",
    "bitty.debug/grantAutomationBearer",
    "bitty.debug/mintAutomationBearer",
    "bitty.debug/elevateAutomation",
    "bitty.debug/issueBearer",
    "bitty.debug/grantBearer",
];

#[test]
fn automation_no_issuance_path_over_ipc_env_or_elevation() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    // No IPC issuance method exists: bypass-shaped names fail closed as
    // unknown methods (registration deny, not scope deny).
    for method in BYPASS_ISSUANCE_METHODS {
        let payload = format!(
            "{{\"id\":1,\"method\":\"{method}\",\"version\":\"1.0\",\"params\":{{\"terminalId\":\"t:1\"}}}}"
        );
        let outcome = handle_envelope(payload.as_bytes(), &dispatcher, &test_context());
        assert!(outcome.was_error, "{method} must not exist");
        assert!(
            response_text(&outcome).contains("UnknownMethod"),
            "{method} must answer UnknownMethod, got: {}",
            response_text(&outcome)
        );
    }
    // Elevation alone never substitutes for a bearer: maximally elevated
    // scopes (the `BITTY_CTL_ELEVATE` allowlist shape, built purely without
    // touching process env) plus forged or hand-crafted tokens still fail
    // closed with zero issued bearers.
    let elevated = crate::ctl::elevation_from_env(Some(
        "debug.control,debug.trace,debug.inspect,terminal.input,terminal.inspect",
    ));
    let ctx = automation_context(&server, elevated, "s1", 0);
    for (id, token) in [
        (11u64, "forged-token".to_string()),
        (12u64, "deadbeef".repeat(4)),
    ] {
        let params = format!(
            "{{\"terminalId\":\"t:1\",\"bearer\":\"{token}\",\"originLabel\":\"h\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
        );
        let outcome = handle_envelope(&synth_envelope(id, &params), &dispatcher, &ctx);
        assert!(outcome.was_error);
        assert!(
            response_text(&outcome).contains("ScopeDenied"),
            "forged bearer with full elevation must be ScopeDenied, got: {}",
            response_text(&outcome)
        );
        let params =
            format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{token}\",\"format\":\"semantic\"}}");
        let outcome = handle_envelope(&capture_envelope(id + 100, &params), &dispatcher, &ctx);
        assert!(outcome.was_error);
        assert!(
            response_text(&outcome).contains("ScopeDenied"),
            "forged capture with full elevation must be ScopeDenied, got: {}",
            response_text(&outcome)
        );
    }
    // Bearer tokens are opaque: a real token embeds neither the session
    // nor the terminal id, so authority cannot be crafted.
    let tok = issue_automation_bearer("sess-9", "t:3", AutomationFamily::Synthesize, 0).unwrap();
    assert_eq!(tok.len(), 32, "token must stay 32 hex chars");
    assert!(tok.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(!tok.contains("sess-9") && !tok.contains("t:3"));
    assert_eq!(automation_bearer_count_for_tests(), 1);
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

#[test]
fn automation_shed_calls_leave_zero_partial_state() {
    // Acceptance item A1.2: overruns shed with typed `budget` errors and
    // leave zero partial state — no sequence advance, no input markers,
    // no audit entries.
    //
    // (Restored: first added under CTX-0660 for #1100, then lost when the
    // trace/record rewrite reworked this file.)
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let tok = issue_automation_bearer("s1", "t:1", AutomationFamily::Synthesize, 0).unwrap();
    let ctx = automation_context(&server, automation_scopes_synthesize(), "s1", 0);
    let params = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"originLabel\":\"load\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    let seq0 = synthetic_seq_for_tests();
    let audit0 = frame_audit_len_for_tests();
    let ring0 = live_input_store().lock().map(|g| g.len()).unwrap_or(0);
    for id in 1..=MAX_SYNTH_CALLS_PER_SEC as u64 {
        let outcome = handle_envelope(&synth_envelope(id, &params), &dispatcher, &ctx);
        assert!(!outcome.was_error, "call {id} must pass under ceiling");
    }
    assert_eq!(
        synthetic_seq_for_tests(),
        seq0 + MAX_SYNTH_CALLS_PER_SEC as u64
    );
    let outcome = handle_envelope(
        &synth_envelope(MAX_SYNTH_CALLS_PER_SEC as u64 + 1, &params),
        &dispatcher,
        &ctx,
    );
    assert!(outcome.was_error);
    let text = response_text(&outcome);
    assert!(
        text.contains("RateLimited") && text.contains("budget"),
        "got: {text}"
    );
    assert_eq!(
        synthetic_seq_for_tests(),
        seq0 + MAX_SYNTH_CALLS_PER_SEC as u64,
        "shed synth must not advance the sequence"
    );
    assert_eq!(
        frame_audit_len_for_tests(),
        audit0,
        "shed synth must not audit"
    );
    assert_eq!(
        live_input_store().lock().map(|g| g.len()).unwrap_or(0),
        ring0 + MAX_SYNTH_CALLS_PER_SEC,
        "shed synth must not publish markers"
    );
    // Same discipline for capture: the shed call appends no audit entry.
    publish_grid_text(vec!["f".to_string()], 0, 1, true, 1, 80, 24);
    let tok = issue_automation_bearer("c1", "t:1", AutomationFamily::Capture, 0).unwrap();
    let ctx = automation_context(&server, automation_scopes_capture(), "c1", 0);
    let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"format\":\"semantic\"}}");
    for id in 1..=MAX_CAPTURE_FPS as u64 {
        let outcome = handle_envelope(&capture_envelope(id, &params), &dispatcher, &ctx);
        assert!(!outcome.was_error, "capture {id} must pass under ceiling");
    }
    let audit_mid = frame_audit_len_for_tests();
    let outcome = handle_envelope(
        &capture_envelope(MAX_CAPTURE_FPS as u64 + 1, &params),
        &dispatcher,
        &ctx,
    );
    assert!(outcome.was_error);
    assert!(
        response_text(&outcome).contains("RateLimited"),
        "got: {}",
        response_text(&outcome)
    );
    assert_eq!(
        frame_audit_len_for_tests(),
        audit_mid,
        "shed capture must not audit"
    );
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

// ── DT-04 admission: per-bearer ceilings, benign sessions unaffected ─────
//
// Acceptance item A1.2: sustained load above one bearer's ceiling sheds
// with typed `budget` errors while a benign concurrent session on another
// bearer keeps serving at the same instant (per-token rate windows —
// shedding never spills across sessions).
#[test]
fn automation_rate_ceiling_is_per_bearer_benign_sessions_unaffected() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let synth_a =
        issue_automation_bearer("sess-a", "t:1", AutomationFamily::Synthesize, 0).unwrap();
    let synth_b =
        issue_automation_bearer("sess-b", "t:2", AutomationFamily::Synthesize, 0).unwrap();
    let ctx_a = automation_context(&server, automation_scopes_synthesize(), "sess-a", 0);
    let ctx_b = automation_context(&server, automation_scopes_synthesize(), "sess-b", 0);
    let params_a = format!(
        "{{\"terminalId\":\"t:1\",\"bearer\":\"{synth_a}\",\"originLabel\":\"load\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    let params_b = format!(
        "{{\"terminalId\":\"t:2\",\"bearer\":\"{synth_b}\",\"originLabel\":\"load\",\"events\":[{{\"type\":\"key\",\"key\":\"a\"}}]}}"
    );
    for id in 1..=MAX_SYNTH_CALLS_PER_SEC as u64 {
        let outcome = handle_envelope(&synth_envelope(id, &params_a), &dispatcher, &ctx_a);
        assert!(
            !outcome.was_error,
            "hot bearer call {id} must pass under ceiling"
        );
    }
    let outcome = handle_envelope(
        &synth_envelope(MAX_SYNTH_CALLS_PER_SEC as u64 + 1, &params_a),
        &dispatcher,
        &ctx_a,
    );
    assert!(outcome.was_error);
    let text = response_text(&outcome);
    assert!(
        text.contains("RateLimited") && text.contains("budget"),
        "hot bearer overrun must shed, got: {text}"
    );
    // Benign session serves at the same instant on its own window.
    let outcome = handle_envelope(
        &synth_envelope(MAX_SYNTH_CALLS_PER_SEC as u64 + 2, &params_b),
        &dispatcher,
        &ctx_b,
    );
    assert!(
        !outcome.was_error,
        "benign session must be unaffected: {}",
        response_text(&outcome)
    );
    // Same discipline for capture.
    publish_grid_text(vec!["f".to_string()], 0, 1, true, 1, 80, 24);
    let cap_a = issue_automation_bearer("sess-a", "t:1", AutomationFamily::Capture, 0).unwrap();
    let cap_b = issue_automation_bearer("sess-b", "t:2", AutomationFamily::Capture, 0).unwrap();
    let ctx_a = automation_context(&server, automation_scopes_capture(), "sess-a", 0);
    let ctx_b = automation_context(&server, automation_scopes_capture(), "sess-b", 0);
    let params_a =
        format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{cap_a}\",\"format\":\"semantic\"}}");
    let params_b =
        format!("{{\"terminalId\":\"t:2\",\"bearer\":\"{cap_b}\",\"format\":\"semantic\"}}");
    for id in 1..=MAX_CAPTURE_FPS as u64 {
        let outcome = handle_envelope(&capture_envelope(id, &params_a), &dispatcher, &ctx_a);
        assert!(
            !outcome.was_error,
            "hot capture {id} must pass under ceiling"
        );
    }
    let outcome = handle_envelope(
        &capture_envelope(MAX_CAPTURE_FPS as u64 + 1, &params_a),
        &dispatcher,
        &ctx_a,
    );
    assert!(outcome.was_error);
    assert!(
        response_text(&outcome).contains("RateLimited"),
        "got: {}",
        response_text(&outcome)
    );
    let outcome = handle_envelope(
        &capture_envelope(MAX_CAPTURE_FPS as u64 + 2, &params_b),
        &dispatcher,
        &ctx_b,
    );
    assert!(
        !outcome.was_error,
        "benign capture must be unaffected: {}",
        response_text(&outcome)
    );
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

// ── DT-04 admission: environment/private-key bytes never reach capture ───
//
// Acceptance item A1.3: environment bytes join seeded secrets and
// clipboard bytes under whole-line redaction in `captureFrame` output;
// benign lines survive verbatim and the response stays labeled
// untrusted observation data.
#[test]
fn automation_capture_redacts_env_and_private_key_lines() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    publish_grid_text(
        vec![
            "AWS_SECRET_KEY=hunter2-env".to_string(),
            "-----BEGIN PRIVATE KEY-----".to_string(),
            "env=TOPSECRET-PLAN".to_string(),
            "deploy token hunter2tok".to_string(),
            "plain hello world".to_string(),
        ],
        0,
        5,
        true,
        13,
        80,
        24,
    );
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let tok = issue_automation_bearer("s1", "t:1", AutomationFamily::Capture, 7000).unwrap();
    let ctx = automation_context(&server, automation_scopes_capture(), "s1", 7000);
    let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\",\"format\":\"semantic\"}}");
    let outcome = handle_envelope(&capture_envelope(1, &params), &dispatcher, &ctx);
    assert!(!outcome.was_error);
    let text = response_text(&outcome);
    for secret in [
        "hunter2-env",
        "BEGIN PRIVATE KEY",
        "TOPSECRET-PLAN",
        "hunter2tok",
    ] {
        assert!(!text.contains(secret), "environment bytes leaked: {text}");
    }
    assert!(
        text.contains("plain hello world"),
        "benign line must survive: {text}"
    );
    assert!(text.contains(REDACTED_MARKER), "got: {text}");
    assert!(
        text.contains("\"trust\":\"untrusted-observation\""),
        "got: {text}"
    );
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

// ── DT-06 admission: sustained ceiling, TTL adequacy, audit byte-accuracy ──
//
// Acceptance: the 120 s TTL and 2/s ceiling stay adequate under harness
// load, and the digest audit stays byte-accurate under contention (every
// attributable call — granted, shed, denied — leaves exactly one entry;
// granted entries carry exactly the served digest).
//
// (Restored: first added under CTX-0660 for #1102, then lost when the
// trace/record rewrite reworked this file.)
#[test]
fn frame_hash_sustained_ceiling_ttl_and_audit_byte_accuracy_under_load() {
    use crate::frame_digest::{FRAME_DIGEST_TTL_MS, MAX_FRAME_DIGEST_PER_SEC, frame_digest_hex};
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    assert_eq!(FRAME_DIGEST_TTL_MS, 120_000);
    assert_eq!(MAX_FRAME_DIGEST_PER_SEC, 2);
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let rgba = fixture_rgba(8, 8, 4);
    publish_frame_rgba(8, 8, 7, rgba.clone());
    let served = frame_digest_hex(8, 8, 7, &rgba);
    let tok = issue_automation_bearer_with_ttl(
        "load",
        "t:1",
        AutomationFamily::FrameDigest,
        0,
        FRAME_DIGEST_TTL_MS,
    )
    .unwrap();
    let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\"}}");
    let forged = "{\"terminalId\":\"t:1\",\"bearer\":\"bogus\"}".to_string();
    let audit0 = frame_audit_len_for_tests();
    let mut id = 1u64;
    // Five consecutive 1 s windows: 2 grants + 1 shed + 1 forged-denied
    // each. Virtual clock only — no sleeps.
    for window in 0..5u64 {
        let now = window * 1_000;
        let ctx = digest_context(&server, automation_scopes_capture(), "load", now);
        for _ in 0..MAX_FRAME_DIGEST_PER_SEC {
            id += 1;
            let outcome = handle_envelope(&digest_envelope(id, &params), &dispatcher, &ctx);
            assert!(
                !outcome.was_error,
                "window {window}: grant must serve under load"
            );
            assert!(
                response_text(&outcome).contains(&served),
                "window {window}: served digest must match: {}",
                response_text(&outcome)
            );
        }
        id += 1;
        let outcome = handle_envelope(&digest_envelope(id, &params), &dispatcher, &ctx);
        assert!(outcome.was_error);
        assert!(
            response_text(&outcome).contains("RateLimited"),
            "window {window}: overrun must shed, got: {}",
            response_text(&outcome)
        );
        id += 1;
        let outcome = handle_envelope(&digest_envelope(id, &forged), &dispatcher, &ctx);
        assert!(outcome.was_error);
        assert!(
            response_text(&outcome).contains("ScopeDenied"),
            "window {window}: forged bearer must deny, got: {}",
            response_text(&outcome)
        );
    }
    // TTL adequacy: the full-cap grant still serves 1 ms before expiry
    // and denies exactly at issue + TTL.
    let ctx = digest_context(&server, automation_scopes_capture(), "load", 119_999);
    id += 1;
    let outcome = handle_envelope(&digest_envelope(id, &params), &dispatcher, &ctx);
    assert!(!outcome.was_error, "grant must serve at TTL - 1 ms");
    assert!(response_text(&outcome).contains(&served));
    let ctx = digest_context(&server, automation_scopes_capture(), "load", 120_000);
    id += 1;
    let outcome = handle_envelope(&digest_envelope(id, &params), &dispatcher, &ctx);
    assert!(outcome.was_error);
    assert!(
        response_text(&outcome).contains("ScopeDenied"),
        "grant must expire exactly at TTL, got: {}",
        response_text(&outcome)
    );
    // Byte-accuracy: 5 windows x (2 granted + 1 shed + 1 denied) + 1
    // granted + 1 expired = 22 entries, no loss, no duplication, no
    // drop-oldest in range (cap is 64).
    let snap = frame_audit_snapshot_for_tests();
    assert_eq!(
        snap.len(),
        audit0 + 22,
        "every attributable call leaves one entry"
    );
    assert!(snap.iter().all(|e| e.format == "digest"));
    assert!(
        snap.iter()
            .all(|e| e.session_id == "load" && e.terminal_id == "t:1"),
        "audit attribution must stay exact under load"
    );
    let with_digest: Vec<_> = snap.iter().filter(|e| !e.digest_hex.is_empty()).collect();
    assert_eq!(with_digest.len(), 11, "exactly the 11 grants carry digests");
    assert!(
        with_digest
            .iter()
            .all(|e| e.digest_hex == served && e.frame_seq == 7),
        "granted entries must carry exactly the served digest"
    );
    let denied: Vec<_> = snap.iter().filter(|e| e.digest_hex.is_empty()).collect();
    assert_eq!(denied.len(), 11, "shed + forged + expired carry no digest");
    assert!(denied.iter().all(|e| e.frame_seq == 0));
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

// ── DT-06 admission: digest-only wire, no pixel channel ───────────────────
//
// Acceptance: `frameHash` answers the equality question in 32 bytes with
// zero pixel bytes on the wire, and no pixel-channel method ships under
// any grant — admitting one needs its own reviewed amendment.
#[test]
fn frame_hash_serves_digest_only_no_pixel_channel() {
    use crate::frame_digest::{FRAME_DIGEST_ALGO, frame_digest_hex};
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    clear_automation_for_tests();
    let server = test_server_info();
    let dispatcher = Dispatcher::with_defaults();
    let rgba = fixture_rgba(8, 8, 4);
    publish_frame_rgba(8, 8, 7, rgba.clone());
    let served = frame_digest_hex(8, 8, 7, &rgba);
    assert_eq!(served.len(), 64, "digest must be 32 bytes hex");
    assert!(served.bytes().all(|b| b.is_ascii_hexdigit()));
    let tok =
        issue_automation_bearer_with_ttl("npx", "t:1", AutomationFamily::FrameDigest, 0, 60_000)
            .unwrap();
    let ctx = digest_context(&server, automation_scopes_capture(), "npx", 0);
    let params = format!("{{\"terminalId\":\"t:1\",\"bearer\":\"{tok}\"}}");
    let outcome = handle_envelope(&digest_envelope(1, &params), &dispatcher, &ctx);
    assert!(!outcome.was_error);
    let text = response_text(&outcome);
    assert!(
        text.contains(&format!("\"digest\":\"{served}\"")),
        "served digest must match: {text}"
    );
    assert!(text.contains(FRAME_DIGEST_ALGO), "got: {text}");
    for key in [
        "\"rgba\"",
        "\"pixels\"",
        "\"bytes\"",
        "\"lines\"",
        "\"grid\"",
        "\"text\"",
        "\"clipboard\"",
        "\"env\"",
        "FRAMEHASH-MARKER-NEVER-ON-WIRE",
    ] {
        assert!(
            !text.contains(key),
            "pixel-channel key {key} on the wire: {text}"
        );
    }
    // No pixel-channel method ships: bypass-shaped names fail closed as
    // unknown methods (registration deny, never scope deny).
    for method in [
        "bitty.debug/framePixels",
        "bitty.debug/getFramePixels",
        "bitty.debug/capturePixels",
    ] {
        let payload = format!(
            "{{\"id\":1,\"method\":\"{method}\",\"version\":\"1.0\",\"params\":{{\"terminalId\":\"t:1\"}}}}"
        );
        let ctx = digest_context(&server, automation_scopes_capture(), "npx", 0);
        let outcome = handle_envelope(payload.as_bytes(), &dispatcher, &ctx);
        assert!(outcome.was_error, "{method} must not exist");
        assert!(
            response_text(&outcome).contains("UnknownMethod"),
            "{method} must answer UnknownMethod, got: {}",
            response_text(&outcome)
        );
    }
    clear_automation_for_tests();
    clear_introspection_for_tests();
}

// ── DT batch2 (CTX-0685): transport hardening + contract + MCP + A3 ──────
//
// Closes #1109 (DT-13), #1107 (DT-11), #1106 (DT-10), #1103 (DT-07/A3).
// Each section pins one issue's acceptance so the four sub-issues stay
// machine-checked from the wire side. All bounds mirror the sibling
// `bitty-devtools` repo (read-only here, never modified).

// ── DT-13 (#1109): transport hardening follow-ups ─────────────────────────
//
// Regression pins for the CTX-0528..0531/0539/0540/0544 hardening line:
// frame bound, JSON depth, RC-9 rate/connection caps, endpoint modes,
// portable socket bound, envelope bounds, and the shared control-queue
// budget. Values are asserted literally so an accidental bound change
// fails fast here instead of silently widening the wire.

#[test]
fn dt13_transport_hardening_bounds_are_pinned() {
    assert_eq!(MAX_FRAME_BYTES, 256 * 1024);
    assert_eq!(crate::wire::MAX_JSON_DEPTH, 32);
    assert_eq!(crate::limits::RC9_REQ_PER_SEC, 100);
    assert_eq!(crate::limits::RC9_BURST_PER_SEC, 200);
    assert_eq!(crate::limits::RC9_MAX_CONNECTIONS, 16);
    assert_eq!(crate::limits::RC9_PAYLOAD_CAP_BYTES, 1024 * 1024);
    #[cfg(unix)]
    {
        assert_eq!(crate::auth::DIR_MODE, 0o700);
        assert_eq!(crate::auth::SOCKET_MODE, 0o600);
    }
    const {
        assert!(MAX_SOCKET_PATH_BYTES <= 100);
    }
    const {
        assert!(MAX_SOCKET_PATH_BYTES < SUN_LEN_MACOS);
    }
    assert_eq!(MAX_PARAMS_BYTES, 4096);
    assert_eq!(MAX_ID_TOKEN_BYTES, 32);
    assert_eq!(MAX_DEVTOOLS_METHOD_BYTES, 128);
    assert_eq!(MAX_METHOD_SUFFIX_LEN, 64);
    assert_eq!(MAX_ERROR_MESSAGE_CHARS, 512);
    assert_eq!(MAX_ECHO_CHARS, 64);
    assert_eq!(DEVTOOLS_PROTOCOL_VERSION, "1.0");
    assert_eq!(DEVTOOLS_METHOD_PREFIX, "bitty.debug/");
    assert_eq!(crate::ctl::CTL_TIMEOUT, std::time::Duration::from_secs(5));
    assert_eq!(crate::ctl::MAX_QUEUED_CONTROLS, 64);
}

#[test]
fn dt13_wire_fail_closed_regression_matrix() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    // Oversize payloads never encode (frame bound first, before dispatch).
    let big = vec![0u8; MAX_FRAME_BYTES + 1];
    assert!(encode_frame(&big).is_err());
    // Deep nesting is rejected before dispatch.
    let nested = "[".repeat(MAX_JSON_DEPTH + 1) + &"]".repeat(MAX_JSON_DEPTH + 1);
    assert!(parse_request(nested.as_bytes()).is_err());
    // Ambient authority fields are rejected outright.
    for field in ["auth", "scope", "role"] {
        let payload = format!(
            "{{\"id\":1,\"method\":\"bitty.debug/ping\",\"version\":\"1.0\",\"{field}\":\"x\"}}"
        );
        let fault = parse_request(payload.as_bytes()).unwrap_err();
        assert_eq!(fault.code, "ForbiddenField");
    }
    let dispatcher = Dispatcher::with_defaults();
    // Version mismatch stays correlated.
    let outcome = handle_envelope(
        br#"{"id":11,"method":"bitty.debug/ping","version":"9.9"}"#,
        &dispatcher,
        &test_context(),
    );
    assert!(outcome.was_error);
    let text = response_text(&outcome);
    assert!(text.contains("UnsupportedVersion"));
    assert!(text.contains("\"id\":11"));
    // Unknown methods fail closed as usage/UnknownMethod (never scope).
    let outcome = handle_envelope(
        br#"{"id":12,"method":"bitty.debug/nope","version":"1.0"}"#,
        &dispatcher,
        &test_context(),
    );
    assert!(outcome.was_error);
    assert!(response_text(&outcome).contains("UnknownMethod"));
    // Connection alone grants no debug scope: read surface denies.
    let bare_server = test_server_info();
    let bare = ServeContext::with_granted_for_tests(&bare_server, crate::scope::ScopeSet::new());
    let outcome = handle_envelope(
        br#"{"id":13,"method":"bitty.debug/getSnapshot","version":"1.0"}"#,
        &dispatcher,
        &bare,
    );
    assert!(outcome.was_error);
    assert!(response_text(&outcome).contains("ScopeDenied"));
    // Socket-path grammar fails closed on length and NUL.
    let long = "a".repeat(MAX_SOCKET_PATH_BYTES + 1);
    assert!(resolve_socket_path(1000, None, Some(&long), None).is_err());
    assert!(resolve_socket_path(1000, None, Some("/tmp/a\0b.sock"), None).is_err());
    clear_introspection_for_tests();
}

// ── DT-11 (#1107): bitty-devtools cross-repo contract ─────────────────────
//
// CONSUMES debug-protocol 1.0 + ctl-envelope: version handshake on every
// read reply, both sibling envelope shapes, and the trace-helper scope
// contract. Guards the `bitty-devtools` parity documented at the top of
// `devtools.rs` (`transport.ts` framing, `protocol.ts` envelope,
// `auth.ts` endpoint).

#[test]
fn dt11_debug_protocol_version_handshake_contract() {
    let dispatcher = Dispatcher::with_defaults();
    let context = test_context();
    // Handshake probe echoes protocol 1.0 over the transport shape.
    let outcome = handle_envelope(
        br#"{"id":21,"method":"bitty.debug/ping","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    let text = response_text(&outcome);
    assert!(text.contains("\"version\":\"1.0\""));
    assert!(text.contains("\"ok\":true"));
    assert!(text.contains("\"id\":21"));
    // Snapshot carries the same version over the protocol shape.
    let outcome = handle_envelope(
        br#"{"jsonrpc":"2.0","id":22,"method":"bitty.debug/getSnapshot","version":"1.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(!outcome.was_error);
    let text = response_text(&outcome);
    assert!(text.contains("\"version\":\"1.0\""));
    assert!(text.contains("\"snapshot\":\"runtime-stats\""));
    // Test-mode handshake advertises the same 1.0 surface version.
    assert_eq!(TEST_SURFACE_PROTOCOL, "1.0");
    assert_eq!(TEST_SURFACE_NAME, "e2e");
    let test_mode = Dispatcher::with_test_mode();
    let outcome = handle_envelope(
        br#"{"id":23,"method":"bitty.debug/testInfo","version":"1.0"}"#,
        &test_mode,
        &context,
    );
    assert!(!outcome.was_error);
    assert!(response_text(&outcome).contains("\"protocol\":\"1.0\""));
    // Wrong version is a correlated usage error, never a silent downgrade.
    let outcome = handle_envelope(
        br#"{"id":24,"method":"bitty.debug/ping","version":"2.0"}"#,
        &dispatcher,
        &context,
    );
    assert!(outcome.was_error);
    let text = response_text(&outcome);
    assert!(text.contains("UnsupportedVersion"));
    assert!(text.contains("\"id\":24"));
}

#[test]
fn dt11_trace_helpers_and_ctl_envelope_contract() {
    let _guard = lock_trace_for_test();
    clear_traces_for_tests();
    let dispatcher = Dispatcher::with_defaults();
    // Trace helpers are registered on the default table (DT-03 surface).
    assert!(dispatcher.contains(METHOD_START_TRACE));
    assert!(dispatcher.contains(METHOD_STOP_TRACE));
    assert!(dispatcher.contains(METHOD_FETCH_TRACE_CHUNK));
    // Trace scope contract: `debug.inspect` alone denies, `debug.trace`
    // serves the params gate (fail-closed before any state).
    let mut inspect_only = crate::scope::ScopeSet::cli_default();
    inspect_only.insert(crate::scope::Scope::DebugInspect);
    let server = test_server_info();
    let inspect_ctx = ServeContext::with_granted_for_tests(&server, inspect_only);
    let outcome = handle_envelope(
        br#"{"id":31,"method":"bitty.debug/startTrace","version":"1.0"}"#,
        &dispatcher,
        &inspect_ctx,
    );
    assert!(outcome.was_error);
    assert!(response_text(&outcome).contains("ScopeDenied"));
    // ctl-envelope: every control verb is registered with its mapped scope.
    for method in crate::ctl::all_control_methods() {
        assert!(dispatcher.contains(method), "{method} must be registered");
        assert!(
            crate::ctl::required_scope_for_ctl_method(method).is_some(),
            "{method} must map to a scope"
        );
    }
    // Unscoped control verbs deny on the debug-protocol taxonomy
    // (`scope`/`ScopeDenied`) and name the elevation allowlist.
    let empty = ServeContext::with_granted_for_tests(&server, crate::scope::ScopeSet::new());
    let outcome = handle_envelope(
        br#"{"id":32,"method":"bitty.debug/listViews","version":"1.0"}"#,
        &dispatcher,
        &empty,
    );
    assert!(outcome.was_error);
    let text = response_text(&outcome);
    assert!(text.contains("ScopeDenied"), "got: {text}");
    assert!(text.contains("BITTY_CTL_ELEVATE"), "got: {text}");
    clear_traces_for_tests();
}

// ── DT-10 (#1106): MCP adapter over debug protocol ─────────────────────────
//
// Thin read-only translation: the v1 default exposes observation only and
// never the automation bearers, trace writers, control verbs, or the
// test-mode surface.

#[test]
fn dt10_mcp_adapter_v1_hides_automation() {
    assert_eq!(MCP_ADAPTER_VERSION, "1.0");
    assert_eq!(DEVTOOLS_PROTOCOL_VERSION, "1.0");
    // Read-only surface is exposed.
    for method in [
        "bitty.debug/ping",
        "bitty.debug/getSnapshot",
        "bitty.debug/getGridText",
        "bitty.debug/getInputRing",
        "bitty.debug/getModifiers",
        "bitty.debug/getFocus",
        "bitty.debug/getProcessStats",
        "bitty.debug/getFrameStats",
        "bitty.debug/streamProcessStats",
        "bitty.debug/streamFrameStats",
        "bitty.debug/fetchTraceChunk",
    ] {
        assert!(
            is_mcp_exposed_debug_method(method),
            "{method} must be MCP-exposed"
        );
        assert!(
            mcp_tool_for_debug_method(method).is_some(),
            "{method} must map to a tool"
        );
    }
    assert_eq!(mcp_tool_names().len(), 11);
    // Automation, trace writers, and test-mode surface stay hidden.
    for method in mcp_denied_debug_methods() {
        assert!(
            !is_mcp_exposed_debug_method(method),
            "{method} must stay hidden"
        );
        assert!(
            mcp_tool_for_debug_method(method).is_none(),
            "{method} must map to no tool"
        );
    }
    assert!(mcp_denied_debug_methods().contains(&METHOD_SYNTHESIZE_INPUT));
    assert!(mcp_denied_debug_methods().contains(&METHOD_CAPTURE_FRAME));
    assert!(mcp_denied_debug_methods().contains(&METHOD_FRAME_HASH));
    assert!(mcp_denied_debug_methods().contains(&METHOD_START_TRACE));
    assert!(mcp_denied_debug_methods().contains(&METHOD_STOP_TRACE));
    assert!(mcp_denied_debug_methods().contains(&METHOD_TEST_INFO));
    assert!(mcp_denied_debug_methods().contains(&METHOD_TEST_EXIT));
    // Control verbs stay hidden too (MCP default is read-only).
    for method in crate::ctl::all_control_methods() {
        assert!(
            !is_mcp_exposed_debug_method(method),
            "control {method} must stay hidden"
        );
        assert!(mcp_tool_for_debug_method(method).is_none());
    }
}

#[test]
fn dt10_mcp_adapter_translation_roundtrip_and_listing() {
    // Bidirectional round-trip over the exposed surface.
    for tool in mcp_tool_names() {
        assert!(
            tool.starts_with(MCP_TOOL_PREFIX),
            "{tool} must carry the prefix"
        );
        let method = debug_method_for_mcp_tool(tool).expect("exposed tool must map");
        assert_eq!(mcp_tool_for_debug_method(method), Some(*tool));
    }
    // Unknown and denied names map to nothing in both directions.
    assert!(debug_method_for_mcp_tool("bitty_debug_nope").is_none());
    assert!(debug_method_for_mcp_tool("bitty_debug_synthesizeInput").is_none());
    assert!(debug_method_for_mcp_tool("other_tool").is_none());
    assert!(mcp_tool_for_debug_method("bitty.debug/synthesizeInput").is_none());
    assert!(mcp_tool_for_debug_method("bitty.debug/testExit").is_none());
    assert!(mcp_tool_for_debug_method("bitty.debug/doesNotExist").is_none());
    // The JSON listing carries the version plus exactly the exposed tools,
    // and never leaks a denied method name.
    let listing = mcp_list_tools_json();
    assert!(listing.contains("\"version\":\"1.0\""));
    for tool in mcp_tool_names() {
        assert!(listing.contains(tool), "listing must contain {tool}");
    }
    for denied in [
        "synthesizeInput",
        "captureFrame",
        "frameHash",
        "startTrace",
        "stopTrace",
        "testInfo",
        "testExit",
        "spawnTerminal",
        "sendInput",
    ] {
        assert!(
            !listing.contains(denied),
            "listing must not leak {denied}: {listing}"
        );
    }
}

// ── DT-07/A3 (#1103): Amendment A3 test-mode E2E acceptance ────────────────
//
// `testInfo`/`testExit` are registration-gated (default-deny), `testExit`
// additionally requires the `debug.control` elevation allowlist, and an
// elevated `testExit` enqueues the deterministic teardown through the
// existing control queue (no new authority, no bypass).

#[test]
fn a3_test_surface_default_deny_even_when_elevated() {
    // Registration is the gate: without test mode even a fully elevated
    // peer gets NotFound (never ScopeDenied, never success).
    let default = Dispatcher::with_defaults();
    let elevated = crate::ctl::elevation_from_env(Some("debug.control"));
    let server = test_server_info();
    let ctx = ServeContext::with_granted_for_tests(&server, elevated);
    for (id, method) in [(41u64, METHOD_TEST_INFO), (42u64, METHOD_TEST_EXIT)] {
        let payload = format!("{{\"id\":{id},\"method\":\"{method}\",\"version\":\"1.0\"}}");
        let outcome = handle_envelope(payload.as_bytes(), &default, &ctx);
        assert!(
            outcome.was_error,
            "{method} must be denied without test mode"
        );
        assert!(
            response_text(&outcome).contains("UnknownMethod"),
            "{method} must answer UnknownMethod, got: {}",
            response_text(&outcome)
        );
    }
}

#[test]
fn a3_test_info_serves_without_scope_in_test_mode() {
    // `testInfo` is read-only surface identity: no scope, no bearer, no
    // terminal content — the only gate is test-mode registration.
    let test_mode = Dispatcher::with_test_mode();
    let server = test_server_info();
    let bare = ServeContext::with_granted_for_tests(&server, crate::scope::ScopeSet::new());
    let outcome = handle_envelope(
        br#"{"id":43,"method":"bitty.debug/testInfo","version":"1.0"}"#,
        &test_mode,
        &bare,
    );
    assert!(!outcome.was_error, "testInfo must serve scoped or not");
    let text = response_text(&outcome);
    assert!(text.contains("\"test_mode\":true"), "got: {text}");
    assert!(text.contains("\"surface\":\"e2e\""), "got: {text}");
    assert!(text.contains("\"protocol\":\"1.0\""), "got: {text}");
    assert!(text.contains("\"instance\":\"test-inst\""), "got: {text}");
    for leaked in [
        "\"grid\"",
        "\"lines\"",
        "\"text\"",
        "\"rgba\"",
        "\"pixels\"",
    ] {
        assert!(
            !text.contains(leaked),
            "testInfo must carry no terminal content ({leaked}): {text}"
        );
    }
}

#[test]
fn a3_test_exit_elevation_matrix_over_wire() {
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    let test_mode = Dispatcher::with_test_mode();
    let server = test_server_info();
    // CLI default holds no debug scope: ScopeDenied with the elevate hint
    // (auth fails before the queue, so no teardown is queued).
    let cli = ServeContext::with_granted_for_tests(&server, crate::scope::ScopeSet::cli_default());
    let outcome = handle_envelope(
        br#"{"id":44,"method":"bitty.debug/testExit","version":"1.0"}"#,
        &test_mode,
        &cli,
    );
    assert!(outcome.was_error);
    let text = response_text(&outcome);
    assert!(text.contains("ScopeDenied"), "got: {text}");
    assert!(text.contains("BITTY_CTL_ELEVATE"), "got: {text}");
    // A misspelled allowlist value grants nothing (fail-closed).
    let bogus = ServeContext::with_granted_for_tests(
        &server,
        crate::ctl::elevation_from_env(Some("debug-control")),
    );
    let outcome = handle_envelope(
        br#"{"id":45,"method":"bitty.debug/testExit","version":"1.0"}"#,
        &test_mode,
        &bogus,
    );
    assert!(outcome.was_error);
    assert!(response_text(&outcome).contains("ScopeDenied"));
    // The explicit allowlist authorizes the teardown path (the queue step
    // itself is owned by the `ctl` queue contract: `CTL_TIMEOUT` budget and
    // `MAX_QUEUED_CONTROLS` cap pinned under DT-13).
    let elevated = crate::ctl::elevation_from_env(Some("debug.control"));
    assert!(
        crate::ctl::authorize_ctl_method(METHOD_TEST_EXIT, &elevated).is_ok(),
        "debug.control elevation must authorize testExit"
    );
    assert_eq!(
        crate::ctl::required_scope_for_ctl_method(METHOD_TEST_EXIT),
        Some(crate::scope::Scope::DebugControl)
    );
    clear_introspection_for_tests();
}

#[test]
fn a3_test_exit_teardown_routes_through_control_queue() {
    // Teardown grants no new authority: `testExit` shares the control-queue
    // path (`handle_control` -> `enqueue_control_and_wait` -> authorize)
    // with every other control verb. Proof here is wire-shape identity plus
    // the authorize gate — the blocking enqueue/drain step itself is owned
    // by the `ctl` queue contract (timed-out waiters withdraw, expired
    // entries never apply) and must not be re-driven from this suite: the
    // queue is process-global and driving it here races the `ctl` tests.
    let _guard = lock_introspection_for_test();
    clear_introspection_for_tests();
    let test_mode = Dispatcher::with_test_mode();
    let server = test_server_info();
    // Registration: test-mode only, exactly one method beyond defaults.
    assert!(test_mode.contains(METHOD_TEST_EXIT));
    assert!(!Dispatcher::with_defaults().contains(METHOD_TEST_EXIT));
    // Wire-shape identity with a sibling control verb: ungranted `testExit`
    // and ungranted `listViews` deny identically (same handler path, same
    // taxonomy, same elevation hint).
    let empty = ServeContext::with_granted_for_tests(&server, crate::scope::ScopeSet::new());
    let exit_outcome = handle_envelope(
        br#"{"id":46,"method":"bitty.debug/testExit","version":"1.0"}"#,
        &test_mode,
        &empty,
    );
    let views_outcome = handle_envelope(
        br#"{"id":47,"method":"bitty.debug/listViews","version":"1.0"}"#,
        &test_mode,
        &empty,
    );
    assert!(exit_outcome.was_error);
    assert!(views_outcome.was_error);
    for (label, outcome) in [("testExit", exit_outcome), ("listViews", views_outcome)] {
        let text = response_text(&outcome);
        assert!(text.contains("ScopeDenied"), "{label} got: {text}");
        assert!(text.contains("BITTY_CTL_ELEVATE"), "{label} got: {text}");
    }
    // Authorize gate: only the `debug.control` elevation opens it.
    let elevated = crate::ctl::elevation_from_env(Some("debug.control"));
    assert!(crate::ctl::authorize_ctl_method(METHOD_TEST_EXIT, &elevated).is_ok());
    let cli = crate::scope::ScopeSet::cli_default();
    assert!(crate::ctl::authorize_ctl_method(METHOD_TEST_EXIT, &cli).is_err());
    clear_introspection_for_tests();
}

// ── plugin-runtime v1 methods (issue #1377) ─────────────────────────────────
//
// The ten accepted devtools-rfc plugin-runtime methods are registered on the
// default table as scope- and param-gated fail-closed stubs: no plugin host
// lives in `bitty-ipc`, so a scoped, well-formed call fails closed with
// `capability`/`PluginRuntimeUnavailable` (on-taxonomy, zero partial state)
// instead of `usage`/`UnknownMethod`. Headless only: no live composer, no
// compositor, no socket I/O.

/// Scope sets for the plugin-runtime matrix: empty, inspect-only,
/// trace-only, control-only, and fully scoped.
fn plugin_runtime_scopes() -> (
    crate::scope::ScopeSet,
    crate::scope::ScopeSet,
    crate::scope::ScopeSet,
    crate::scope::ScopeSet,
    crate::scope::ScopeSet,
) {
    use crate::scope::Scope::{DebugControl, DebugInspect, DebugTrace};
    let mut inspect = crate::scope::ScopeSet::new();
    inspect.insert(DebugInspect);
    let mut trace = crate::scope::ScopeSet::new();
    trace.insert(DebugTrace);
    let mut control = crate::scope::ScopeSet::new();
    control.insert(DebugControl);
    let mut full = crate::scope::ScopeSet::new();
    full.insert(DebugInspect);
    full.insert(DebugTrace);
    full.insert(DebugControl);
    (crate::scope::ScopeSet::new(), inspect, trace, control, full)
}

fn plugin_runtime_envelope(method: &str, params: &str) -> Vec<u8> {
    format!("{{\"id\":1,\"method\":\"{method}\",\"version\":\"1.0\",\"params\":{params}}}")
        .into_bytes()
}

#[test]
fn plugin_runtime_v1_methods_registered_and_mcp_hidden() {
    // Every accepted v1 method from the RFC table is callable (registered),
    // and none is advertised as an MCP tool (fail-closed stubs must not
    // promise data the server cannot serve).
    let dispatcher = Dispatcher::with_defaults();
    for method in [
        METHOD_LIST_PLUGINS,
        METHOD_GET_PLUGIN,
        METHOD_LIST_SUBSCRIPTIONS,
        METHOD_GET_BUDGETS,
        METHOD_GET_QUEUE_SNAPSHOT,
        METHOD_LIST_HANDLES,
        METHOD_STREAM_EVENTS,
        METHOD_SUSPEND_HANDLER,
        METHOD_RESUME_PLUGIN,
        METHOD_DISPOSE_GENERATION,
    ] {
        assert!(dispatcher.contains(method), "{method} must be registered");
        assert!(
            !is_mcp_exposed_debug_method(method),
            "{method} must stay MCP-hidden"
        );
        assert!(
            mcp_tool_for_debug_method(method).is_none(),
            "{method} must map to no MCP tool"
        );
        assert!(
            mcp_denied_debug_methods().contains(&method),
            "{method} must be MCP-denied"
        );
    }
}

#[test]
fn plugin_runtime_scope_matrix_per_rfc() {
    // RFC scope table: six readers need `debug.inspect` (any debug scope
    // reads), `streamEvents` needs `debug.trace` (or `control`), and the
    // three lifecycle verbs need exactly `debug.control`. Connection alone
    // grants nothing: every method denies with `scope`/`ScopeDenied`.
    let dispatcher = Dispatcher::with_defaults();
    let server = test_server_info();
    let (empty, inspect, trace, control, _full) = plugin_runtime_scopes();
    let readers = [
        (METHOD_LIST_PLUGINS, "{\"generation\":null}"),
        (METHOD_GET_PLUGIN, "{\"pluginId\":\"p\"}"),
        (METHOD_LIST_SUBSCRIPTIONS, "{\"pluginId\":\"p\"}"),
        (METHOD_GET_BUDGETS, "{\"pluginId\":\"p\",\"generation\":2}"),
        (METHOD_GET_QUEUE_SNAPSHOT, "{\"pluginId\":\"p\"}"),
        (METHOD_LIST_HANDLES, "{\"pluginId\":\"p\"}"),
    ];
    let stream = [(
        METHOD_STREAM_EVENTS,
        "{\"types\":[\"a\"],\"batch\":{\"maxEvents\":8,\"maxBytes\":1024}}",
    )];
    let verbs = [
        (
            METHOD_SUSPEND_HANDLER,
            "{\"pluginId\":\"p\",\"handlerId\":\"h\",\"cause\":\"c\"}",
        ),
        (
            METHOD_RESUME_PLUGIN,
            "{\"pluginId\":\"p\",\"generation\":2}",
        ),
        (
            METHOD_DISPOSE_GENERATION,
            "{\"pluginId\":\"p\",\"generation\":2}",
        ),
    ];
    // Zero scopes: everything denies with typed scope, zero partial state.
    for (method, params) in readers.iter().chain(stream.iter()).chain(verbs.iter()) {
        let ctx = ServeContext::with_granted_for_tests(&server, empty.clone());
        let outcome = handle_envelope(&plugin_runtime_envelope(method, params), &dispatcher, &ctx);
        assert!(outcome.was_error, "{method} must deny with zero scopes");
        let text = response_text(&outcome);
        assert_eq!(
            error_category(&text).as_deref(),
            Some("scope"),
            "{method} denial must be typed scope: {text}"
        );
        assert!(
            text.contains("\"code\":\"ScopeDenied\""),
            "{method} got: {text}"
        );
    }
    // Inspect-only: readers are callable (fail-closed stub verdict, not a
    // scope denial); the stream and the verbs still deny.
    let inspect_ctx = ServeContext::with_granted_for_tests(&server, inspect);
    for (method, params) in readers {
        let outcome = handle_envelope(
            &plugin_runtime_envelope(method, params),
            &dispatcher,
            &inspect_ctx,
        );
        assert!(outcome.was_error, "{method} stub must fail closed");
        let text = response_text(&outcome);
        assert!(
            text.contains("PluginRuntimeUnavailable"),
            "{method} got: {text}"
        );
    }
    for (method, params) in stream.iter().chain(verbs.iter()) {
        let outcome = handle_envelope(
            &plugin_runtime_envelope(method, params),
            &dispatcher,
            &inspect_ctx,
        );
        assert!(outcome.was_error, "{method} must deny inspect-only");
        assert!(
            response_text(&outcome).contains("ScopeDenied"),
            "{method} got: {}",
            response_text(&outcome)
        );
    }
    // Trace-only: the stream is callable; the control verbs still deny.
    let trace_ctx = ServeContext::with_granted_for_tests(&server, trace);
    let outcome = handle_envelope(
        &plugin_runtime_envelope(stream[0].0, stream[0].1),
        &dispatcher,
        &trace_ctx,
    );
    assert!(outcome.was_error);
    assert!(
        response_text(&outcome).contains("PluginRuntimeUnavailable"),
        "streamEvents got: {}",
        response_text(&outcome)
    );
    for (method, params) in verbs {
        let outcome = handle_envelope(
            &plugin_runtime_envelope(method, params),
            &dispatcher,
            &trace_ctx,
        );
        assert!(outcome.was_error, "{method} must deny trace-only");
        assert!(
            response_text(&outcome).contains("ScopeDenied"),
            "{method} got: {}",
            response_text(&outcome)
        );
    }
    // Control-only: the verbs are callable.
    let control_ctx = ServeContext::with_granted_for_tests(&server, control);
    for (method, params) in verbs {
        let outcome = handle_envelope(
            &plugin_runtime_envelope(method, params),
            &dispatcher,
            &control_ctx,
        );
        assert!(outcome.was_error, "{method} stub must fail closed");
        assert!(
            response_text(&outcome).contains("PluginRuntimeUnavailable"),
            "{method} got: {}",
            response_text(&outcome)
        );
    }
}

#[test]
fn plugin_runtime_param_gates_generation_ownership() {
    // Generation ownership at the wire boundary: resources are addressed as
    // `(pluginId, generation)`. Malformed addresses fail closed with
    // `usage`/`InvalidParams` before any stub verdict; well-formed ones
    // reach the `capability` stub verdict.
    let dispatcher = Dispatcher::with_defaults();
    let server = test_server_info();
    let (_empty, _inspect, _trace, _control, full) = plugin_runtime_scopes();
    let ctx = ServeContext::with_granted_for_tests(&server, full);
    // (method, params, expect_invalid_params)
    let probes: &[(&str, &str, bool)] = &[
        (METHOD_LIST_PLUGINS, "{}", false),
        (METHOD_LIST_PLUGINS, "{\"generation\":null}", false),
        (METHOD_LIST_PLUGINS, "{\"generation\":3}", false),
        (METHOD_LIST_PLUGINS, "{\"generation\":0}", true),
        (METHOD_LIST_PLUGINS, "{\"generation\":\"3\"}", true),
        (METHOD_GET_PLUGIN, "{\"pluginId\":\"p\"}", false),
        (METHOD_GET_PLUGIN, "{}", true),
        (METHOD_GET_PLUGIN, "{\"pluginId\":\"\"}", true),
        (METHOD_LIST_SUBSCRIPTIONS, "{\"pluginId\":\"p\"}", false),
        (METHOD_LIST_SUBSCRIPTIONS, "{}", true),
        (
            METHOD_GET_BUDGETS,
            "{\"pluginId\":\"p\",\"generation\":2}",
            false,
        ),
        (METHOD_GET_BUDGETS, "{\"pluginId\":\"p\"}", true),
        (
            METHOD_GET_BUDGETS,
            "{\"pluginId\":\"p\",\"generation\":0}",
            true,
        ),
        (METHOD_GET_QUEUE_SNAPSHOT, "{\"pluginId\":\"p\"}", false),
        (METHOD_GET_QUEUE_SNAPSHOT, "{\"pluginId\":\"\"}", true),
        (METHOD_LIST_HANDLES, "{\"pluginId\":\"p\"}", false),
        (METHOD_LIST_HANDLES, "[]", true),
        (
            METHOD_STREAM_EVENTS,
            "{\"types\":[\"a\"],\"batch\":{\"maxEvents\":8,\"maxBytes\":1024}}",
            false,
        ),
        (METHOD_STREAM_EVENTS, "{}", true),
        (
            METHOD_STREAM_EVENTS,
            "{\"types\":[],\"batch\":{\"maxEvents\":8,\"maxBytes\":1024}}",
            true,
        ),
        (
            METHOD_STREAM_EVENTS,
            "{\"types\":[\"a\"],\"batch\":{\"maxEvents\":0,\"maxBytes\":1024}}",
            true,
        ),
        (
            METHOD_STREAM_EVENTS,
            "{\"types\":[\"a\"],\"batch\":{\"maxEvents\":8,\"maxBytes\":0}}",
            true,
        ),
        (
            METHOD_SUSPEND_HANDLER,
            "{\"pluginId\":\"p\",\"handlerId\":\"h\",\"cause\":\"c\"}",
            false,
        ),
        (
            METHOD_SUSPEND_HANDLER,
            "{\"pluginId\":\"p\",\"handlerId\":\"h\"}",
            true,
        ),
        (
            METHOD_SUSPEND_HANDLER,
            "{\"pluginId\":\"p\",\"handlerId\":\"\",\"cause\":\"c\"}",
            true,
        ),
        (
            METHOD_RESUME_PLUGIN,
            "{\"pluginId\":\"p\",\"generation\":2}",
            false,
        ),
        (METHOD_RESUME_PLUGIN, "{\"pluginId\":\"p\"}", true),
        (
            METHOD_DISPOSE_GENERATION,
            "{\"pluginId\":\"p\",\"generation\":2}",
            false,
        ),
        (
            METHOD_DISPOSE_GENERATION,
            "{\"pluginId\":\"p\",\"generation\":0}",
            true,
        ),
    ];
    for (method, params, expect_invalid) in probes {
        let outcome = handle_envelope(&plugin_runtime_envelope(method, params), &dispatcher, &ctx);
        assert!(outcome.was_error, "{method} {params} must fail closed");
        let text = response_text(&outcome);
        if *expect_invalid {
            assert_eq!(
                error_category(&text).as_deref(),
                Some("usage"),
                "{method} {params} must be typed usage: {text}"
            );
            assert!(
                text.contains("\"code\":\"InvalidParams\""),
                "{method} {params} got: {text}"
            );
        } else {
            assert_eq!(
                error_category(&text).as_deref(),
                Some("capability"),
                "{method} {params} must be typed capability: {text}"
            );
            assert!(
                text.contains("\"code\":\"PluginRuntimeUnavailable\""),
                "{method} {params} got: {text}"
            );
        }
        assert!(
            ACCEPTED_DEBUG_CATEGORIES.contains(&error_category(&text).unwrap().as_str()),
            "{method} {params} off-taxonomy: {text}"
        );
    }
}
