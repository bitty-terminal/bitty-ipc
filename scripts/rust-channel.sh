#!/usr/bin/env bash
# rust-channel.sh — print the Rust channel pinned in rust-toolchain.toml.
#
# Single source of truth for the toolchain channel. The release workflow
# resolves its `dtolnay/rust-toolchain` installs and the provenance record
# through this script instead of repeating the channel literal in the build
# matrix, the Alpine job, and the provenance JSON (CTX-0502, #824 review
# minor). rustup reads the same file directly for local development.
#
# Usage:
#   scripts/rust-channel.sh [--file PATH]
#
# Options:
#   --file PATH  Toolchain file to read (default: <repo>/rust-toolchain.toml).
#   -h, --help   Show this help.
#
# Exit codes: 0 = channel printed, 1 = missing/unparseable channel,
# 2 = usage error.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILE="$REPO_ROOT/rust-toolchain.toml"

usage() {
	cat <<'EOF'
Usage: scripts/rust-channel.sh [--file PATH]

Print the `channel` from the [toolchain] table of rust-toolchain.toml.

Options:
  --file PATH  Toolchain file to read (default: <repo>/rust-toolchain.toml).
  -h, --help   Show this help.
EOF
}

fail() {
	printf 'rust-channel: FAIL: %s\n' "$*" >&2
	exit 1
}

while (($#)); do
	case "$1" in
	--file)
		[[ $# -ge 2 ]] || fail "--file needs a value"
		FILE="$2"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage >&2
		exit 2
		;;
	esac
done

[[ -f "$FILE" ]] || fail "toolchain file not found: $FILE"

channel="$(awk '
	/^\[toolchain\][[:space:]]*$/ { section = 1; next }
	/^\[/ { section = 0 }
	section && /^[[:space:]]*channel[[:space:]]*=/ {
		line = $0
		sub(/^[^=]*=[[:space:]]*/, "", line)
		gsub(/^["\047]/, "", line)
		gsub(/["\047][[:space:]]*$/, "", line)
		print line
		exit
	}
' "$FILE")"

[[ -n "$channel" ]] || fail "no channel in [toolchain] of $FILE"
printf '%s\n' "$channel"
