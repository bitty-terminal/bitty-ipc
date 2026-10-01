# bitty-ipc

Bitty L1 Rust Core Extension: generic out-of-process IPC bridge boundary.

## Architecture

bitty-ipc is split into focused, composable crates for fine-grained plugin dependencies:

```
bitty-ipc-api        # Pure API layer (zero dependencies)
    ↑
bitty-ipc-core       # Framing, wire, limits, transport
    ↑
bitty-ipc-auth       # Platform auth (rustix/nix)
bitty-ipc-devtools   # DevTools protocol
bitty-ipc-mcp        # MCP adapter
    ↑
bitty-ipc            # Full implementation (BridgeClient)
```

### Crates

- **`bitty-ipc-api`** — Pure types (zero dependencies): error types, scope definitions, wire envelope types, frame types, channel types. This is the only crate plugins and cross-repo consumers depend on for API contracts.

- **`bitty-ipc-core`** — Core implementation: bounded framing (encode/decode), wire protocol v1, rate limits (RC-9/RC-10), transport stubs, no platform-specific code.

- **`bitty-ipc-auth`** — Platform authentication: peer credential verification via `rustix` (Linux) and `nix` (macOS/BSD), UID verification, child token management, socket/directory mode checks.

- **`bitty-ipc-devtools`** — DevTools protocol: `bitty.debug/*` method dispatch, snapshot/ctl/tool_dispatch protocols, headless request parsing.

- **`bitty-ipc-mcp`** — MCP adapter: `McpClientStub` with bounded framing, correlation, deterministic timeouts.

- **`bitty-ipc`** — Full implementation: `BridgeClient` composing method registry, scope authorization, consent ledger, bounded endpoint. The published boundary for `bitty-ai`, devtools, and out-of-process consumers.

## Status

Extracted from Bitty Core (CTX-0916, Issue #1585) following the bitty-network pattern. Implements the accepted IPC-Agent RFC (OQ-018, accepted 2026-08-29). General IPC infrastructure for DevTools, Headless, Sandbox, Panel extensions, and AI plugins.

## Use Cases

- **DevTools**: Performance profilers, log viewers, terminal state inspectors
- **Headless**: CI/CD integration, automated testing, remote control
- **Sandbox**: Isolated plugin execution with scope-based permissions
- **Panel Extensions**: Custom panels needing real-time terminal data
- **AI Plugins**: Foundation for bitty-agent AI protocol layer

## Features

```toml
[features]
default = []
test-support = []  # Hermetic test entry points (dev-only)
```

## Plugin Usage

### Minimal - API types only

```toml
[dependencies]
bitty-ipc-api = "0.1"
```

### Core IPC with framing

```toml
[dependencies]
bitty-ipc-api = "0.1"
bitty-ipc-core = "0.1"
```

### Full IPC client

```toml
[dependencies]
bitty-ipc = "0.1"
```

### DevTools protocol

```toml
[dependencies]
bitty-ipc-devtools = "0.1"
```

## Trust Boundary

Every byte crossing the IPC/MCP boundary is treated as **untrusted** per ADR-0003:

- Hard frame-payload bound: 256 KiB per message (RC-10)
- Bounded channels/transport and pending table (RC-9)
- Method-name RFC grammar validation before dispatch
- Peer-credential UID equality before parsing
- Per-request scope evaluation server-side
- Fail-closed overflow and countable shedding

## Documentation

- Architecture: See crate-level docs in each `crates/*/src/lib.rs`
- Security: [bitty-docs threat model](https://github.com/bitty-terminal/bitty-docs/blob/main/docs/security/threat-model.md)
- RFC: [IPC-Agent RFC](https://github.com/bitty-terminal/bitty-ai-docs/blob/main/specifications/ipc-agent-rfc.md)
- API Documentation: `cargo doc --workspace --no-deps --open`

## Layout

- `crates/` — workspace members (bitty-ipc-api, bitty-ipc-core, bitty-ipc-auth, bitty-ipc-devtools, bitty-ipc-mcp, bitty-ipc)

## Gates

`just check` (fmt + clippy `-D warnings` + test). Rust channel pinned in `rust-toolchain.toml`; MSRV 1.85 (`rust-version` in workspace root).

## License

MIT OR Apache-2.0
