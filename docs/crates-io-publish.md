# crates.io publish runbook: bitty-ipc workspace

Priority: P2 | Area: area:packaging | Labels: feat,P2,area:packaging
| Milestone: v0.1.0 | Issue: bitty-ipc#17
| Upstream: bitty-terminal/bitty#1512

Scope is this repository only. This note records the ordered first publish
of the 6 workspace crates at version `0.0.1`, so the owner can execute it
after the registry token rotation lands (see the Blockers section).

## Readiness (verified)

- All 6 crate names return "does not exist" on the crates.io API: free.
- `cargo publish --dry-run -p bitty-ipc-api` is green (packaged, verified,
  upload aborted as expected for a dry run).
- `bitty-ipc-core` and `bitty-ipc-auth` dry-runs fail only with
  "no matching package named `bitty-ipc-api` found", which is the expected
  ordered-publish signal: every path dependency already carries an explicit
  `version = "0.0.1"`, so no manifest change is needed.
- `bitty-ipc-devtools` resolves `sha2` to the locked `0.11.0` release, which
  exists on crates.io; the `0.11.0-pre.5` requirement line needs no change
  for publishing.

## Prerequisites

- The registry token rotation recorded upstream is complete. Never publish
  with a token that may have been exposed; each publish is permanent
  (yank is the only undo).
- Immediately before publishing, re-check that all six crate names are still
  free on the crates.io API. Names are first-come-first-served; the readiness
  check above is point-in-time and the publish may run days after this note.
- The working tree is clean and on `main`; the crates to publish are
  unchanged since the dry-run verification above.

## Ordered publish commands

Run from the repository root, one step at a time. After each step, wait
until the crate version is visible in the crates.io index (a few minutes)
before the next step; if a later step reports "no matching package", wait
and retry rather than forcing anything.

```sh
cargo publish -p bitty-ipc-api
cargo publish -p bitty-ipc-core
cargo publish -p bitty-ipc-auth
cargo publish -p bitty-ipc-devtools
cargo publish -p bitty-ipc-mcp
cargo publish -p bitty-ipc
```

`bitty-ipc-core` and `bitty-ipc-auth` are independent of each other once
`-api` is live, so their relative order does not matter; the same holds for
`-devtools` and `-mcp` once api/core/auth are live. The umbrella `bitty-ipc`
goes last. The optional `mcp` feature stays default-off; publishing does not
change feature wiring.

## Verification

- After each step, confirm the just-published crate is visible in the index
  (`cargo search <crate> --limit 1` for the crate from that step; repeat for
  all six: `bitty-ipc-api`, `bitty-ipc-core`, `bitty-ipc-auth`,
  `bitty-ipc-devtools`, `bitty-ipc-mcp`, `bitty-ipc`).
- Every crate page on crates.io shows "Builds on docs.rs" once the docs
  build finishes.
- Downstream check: a clean scratch crate depending on
  `bitty-ipc = "0.0.1"` builds with `--locked`-style reproducible resolution
  (no path or git override needed).
