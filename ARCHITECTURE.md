# bitty-ipc Architecture

## Overview

`bitty-ipc` is the generic out-of-process IPC bridge infrastructure for Bitty Terminal, extracted from Core following the "small core" principle (like `bitty-network`).

## Layered Architecture

The repository follows a strict layered design to maximize reusability and minimize dependencies:

```
bitty-ipc-api (zero dependencies)
    ↓
bitty-ipc-core (framing, transport)
    ↓
bitty-ipc-auth (platform auth)
    ↓
├─ bitty-ipc-devtools (DevTools protocol)
├─ bitty-ipc-mcp (MCP adapter)
└─ bitty-ipc (full implementation)
```

## Crate Responsibilities

### `bitty-ipc-api` (zero dependencies)

Pure type definitions with zero external dependencies:

- `error.rs`: `IpcError` enum
- `scope.rs`: Scope/permission types (`Scope`, `ScopeSet`, `ConsentLedger`)
- Wire envelope types (frame/channel types)

### `bitty-ipc-core`

Core IPC primitives:

- `frame.rs`: Binary framing layer
- `wire.rs`: Wire protocol encoding/decoding
- `transport.rs`: Unix domain socket transport
- `limits.rs`: Protocol bounds and limits
- `channel.rs`: Request/response channel types

### `bitty-ipc-auth`

Platform-specific authentication (Linux/Unix):

- `auth.rs`: Peer credential verification (`verify_peer_for_connection`)
- `peer.rs`: `StreamIdentity`, `VerifiedPeer`, `PeerCredentials`
- Uses `rustix` for SO_PEERCRED socket option

### `bitty-ipc-devtools`

DevTools protocol implementation:

- `devtools.rs`: Core DevTools server/client
- `ctl.rs`: Control channel (131KB, complex state machine)
- `snapshot.rs`: Terminal snapshot service (DIR-018 bounded DTO)
- `tool_dispatch.rs`: Tool routing/dispatch
- `frame_digest.rs`: Frame integrity verification

### `bitty-ipc-mcp`

MCP (Model Context Protocol) adapter:

- Converts generic IPC wire format to MCP JSON-RPC protocol
- Enables LLM tools to interact with Bitty via standardized protocol

### `bitty-ipc` (umbrella crate)

Full implementation integrating all layers:

- `bridge.rs`: `BridgeClient` - generic client boundary
- `host_bridge.rs`: `HostBridge` - server-side host interface
- `execution.rs`: Process execution substrate
- `execution_verbs.rs`: Execution verb types
- `rich_fragment.rs`: Rich text fragments for responses
- Re-exports all sub-crates for one-stop API

## Design Principles

### Zero AI Vocabulary

This is generic IPC infrastructure. AI-specific semantics live in `bitty-ai`, not here.

### Fail-Closed by Default

Unknown methods, unregistered scopes, and unverified peers are rejected. The registry must explicitly allow operations.

### Bounded Everything

All buffers, queues, and data structures have compile-time or runtime bounds to prevent resource exhaustion.

### Platform Isolation

Platform-specific code (Linux SO_PEERCRED, macOS getpeereid) stays isolated in `bitty-ipc-auth`.

## Integration Points

### Consumer Projects

- `bitty` (Core runtime): Uses for DevTools IPC bridge
- `bitty-ai`: Uses for agent/LLM tool communication via MCP adapter
- External devtools clients: Connect via Unix domain sockets

### Dependencies

- `rustix`: Platform syscalls (SO_PEERCRED)
- `serde`/`serde_json`: MCP JSON-RPC encoding
- No network crates, no AI crates

## Test Strategy

Tests live in each crate:

- `bitty-ipc-auth`: Peer verification, credential extraction
- `bitty-ipc-core`: Frame encoding/decoding, transport reliability
- `bitty-ipc-devtools`: DevTools protocol compliance, snapshot bounds
- Integration tests in `bitty-ipc/tests/`: End-to-end IPC flows

## Future Work

- [ ] Windows named pipe support in `bitty-ipc-auth`
- [ ] macOS getpeereid support in `bitty-ipc-auth`
- [ ] `bitty-ipc-lua`: Lua FFI bindings for plugin access
- [ ] Async/await transport layer (currently synchronous)
