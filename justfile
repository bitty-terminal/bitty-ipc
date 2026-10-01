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

actionlint:
    actionlint -color
