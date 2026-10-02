# bitty-ipc

An independent L1 Rust Core Extension, extracted from [`bitty`](https://github.com/bitty-terminal/bitty) (Bitty Core): a generic out-of-process IPC bridge boundary (DevTools/MCP protocols, bounded framing, peer-credential auth, scope-based consent).

## Status

Pre-1.0 (`version = "0.0.1"` across every crate in this workspace). Extracted from Bitty Core (CTX-0916, Issue #1585) following the `bitty-network` pattern. Implements the accepted IPC-Agent RFC (`OQ-018`, accepted 2026-08-29). General IPC infrastructure for DevTools, Headless, Sandbox, Panel extensions, and AI plugins. Not yet published to crates.io; see [Consuming from Bitty Core](#consuming-from-bitty-core) for the current pin pattern.

## Architecture

bitty-ipc is split into focused, composable crates for fine-grained plugin dependencies:

```
bitty-ipc-api        # Pure API layer (zero dependencies)
    ↑
bitty-ipc-core       # Framing, wire, limits, transport
    ↑
bitty-ipc-auth       # Platform auth (rustix/nix)
bitty-ipc-devtools   # DevTools protocol
bitty-ipc-mcp        # MCP adapter (optional, `mcp` feature)
    ↑
bitty-ipc            # Full implementation (BridgeClient)
```

### Crates

| Crate | Role |
|---|---|
| [`bitty-ipc-api`](crates/bitty-ipc-api) | Pure types (zero dependencies): error types, scope definitions, wire envelope types, frame types, channel types. The only crate plugins and cross-repo consumers depend on for API contracts. |
| [`bitty-ipc-core`](crates/bitty-ipc-core) | Core implementation: bounded framing (encode/decode), wire protocol v1, rate limits (RC-9/RC-10), transport stubs, no platform-specific code. |
| [`bitty-ipc-auth`](crates/bitty-ipc-auth) | Platform authentication: peer credential verification via `rustix` (Linux) and `nix` (macOS/BSD), UID verification, child token management, socket/directory mode checks. |
| [`bitty-ipc-devtools`](crates/bitty-ipc-devtools) | DevTools protocol: `bitty.debug/*` method dispatch, snapshot/ctl/tool_dispatch protocols, headless request parsing. |
| [`bitty-ipc-mcp`](crates/bitty-ipc-mcp) | MCP adapter: `McpClientStub` with bounded framing, correlation, deterministic timeouts. Optional on the facade (`mcp` feature, default-off). |
| [`bitty-ipc`](crates/bitty-ipc) | Full implementation: `BridgeClient` composing method registry, scope authorization, consent ledger, bounded endpoint. The published boundary for `bitty-ai`, devtools, and out-of-process consumers. |

## Use Cases

- **DevTools**: Performance profilers, log viewers, terminal state inspectors
- **Headless**: CI/CD integration, automated testing, remote control
- **Sandbox**: Isolated plugin execution with scope-based permissions
- **Panel Extensions**: Custom panels needing real-time terminal data
- **AI Plugins**: Foundation for `bitty-agent`'s AI protocol layer

## Features

```toml
[features]
default = []
test-support = []  # Hermetic test entry points (dev-only; also on bitty-ipc-auth)
mcp = ["bitty-ipc-mcp"]  # Optional MCP adapter (McpClientStub); default-off
```

`bitty-ipc-mcp` is an optional dependency gated behind the `mcp` feature,
following the default-off posture `bitty-terminal-docs`
`architecture/core-boundaries.md` describes for `ipc-mcp`. Bitty Core uses
nothing from the MCP adapter outside tests, so it stays out of the release
dependency tree unless a consumer opts in:

```toml
[dependencies]
bitty-ipc = { git = "https://github.com/bitty-terminal/bitty-ipc", rev = "<sha>", features = ["mcp"] }
```

## Consuming from Bitty Core

Bitty Core (`bitty/`) depends on this repository as an exact-rev Git dependency, never a branch or tag, per workspace policy:

```toml
[dependencies]
bitty-ipc = { git = "https://github.com/bitty-terminal/bitty-ipc", rev = "<40-or-7-char-sha>" }
# or any individual crate, e.g.:
bitty-ipc-api = { git = "https://github.com/bitty-terminal/bitty-ipc", rev = "<40-or-7-char-sha>" }
```

Enable `test-support` on `bitty-ipc` (and `bitty-ipc-auth` where needed) only in `[dev-dependencies]`:

```toml
[dev-dependencies]
bitty-ipc = { git = "https://github.com/bitty-terminal/bitty-ipc", rev = "<sha>", features = ["test-support"] }
```

Bump the pin only through a scoped task once this repo's `main` is green; never point at a branch name before a tagged release.

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

- `crates/` — workspace members (`bitty-ipc-api`, `bitty-ipc-core`, `bitty-ipc-auth`, `bitty-ipc-devtools`, `bitty-ipc-mcp`, `bitty-ipc`)

## Build and test

All quality gates run through the [`justfile`](justfile), never bare tool invocations:

```sh
just check        # fmt-check + clippy -D warnings + test
just fmt-check
just clippy
just test
just typecheck
just actionlint
```

Toolchain channel is pinned in [`rust-toolchain.toml`](rust-toolchain.toml); MSRV is `1.85` (`rust-version` in the workspace root `Cargo.toml`).

## License

MIT OR Apache-2.0
