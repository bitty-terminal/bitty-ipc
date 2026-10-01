# CarryCtx Configuration

This directory holds the persistent CarryCtx configuration for the bitty-ipc repository.

## Files

- `config.toml`: Project configuration (branch templates, cleanup policies, verification commands)
- `state.sqlite`: Task, session, and checkpoint state (gitignored)
- `config.local.toml`: Local overrides (gitignored, optional)

## Key Settings

- **Task prefix**: `CTX` (e.g., CTX-0001)
- **Main branch**: `main`
- **Branch template**: `carryctx/{task_id}-{slug}`
- **Worktree cleanup**: `when_idle` on completion, `keep` on cancellation
- **Session staleness**: 2 hours
- **Checkpoint**: Required before session end

Refer to the [CarryCtx documentation](https://github.com/uniphil/carryctx) for detailed configuration options.
