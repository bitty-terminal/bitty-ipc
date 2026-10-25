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

# Non-default-feature gate (`test-support`): proves the hermetic test entry
# points still build and test clean when the feature is enabled for
# downstream consumers.
check-all-features:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --all-targets --all-features --locked

actionlint:
    actionlint -color

# Publish a redacted CarryCtx snapshot to refs/heads/carryctx-snapshots.
workflow-publish:
    ./scripts/workflow-publish.sh

# Fetch and import the published CarryCtx snapshot (fresh-clone recovery).
workflow-import:
    git fetch origin refs/heads/carryctx-snapshots:refs/remotes/origin/carryctx-snapshots
    carryctx import --from-git refs/remotes/origin/carryctx-snapshots
