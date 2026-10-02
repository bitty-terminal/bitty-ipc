# bitty-ipc quality gates (run via justfile, never bare).
check:
    just fmt-check
    just clippy
    just test

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings

test:
    cargo test --workspace --all-targets --locked

typecheck:
    cargo check --workspace --all-targets --locked

# Non-default-feature gate (`mcp`): proves the optional MCP adapter still
# builds and tests clean when enabled (CTX-0004).
check-all-features:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-targets --all-features --locked

actionlint:
    actionlint -color
