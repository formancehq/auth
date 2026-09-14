#!/usr/bin/env bash
set -euo pipefail

imports_path="${1:?usage: validate-imports.sh IMPORTS_FILE}"
expected="$(mktemp)"
actual="$(mktemp)"
trap 'rm -f "$expected" "$actual"' EXIT

printf '%s\n' \
  'wasi:cli/environment@0.2.12' \
  'wasi:clocks/monotonic-clock@0.2.12' \
  'wasi:clocks/wall-clock@0.2.12' \
  'wasi:io/poll@0.2.12' \
  'wasi:random/random@0.2.12' > "$expected"
LC_ALL=C sort "$imports_path" > "$actual"

if ! cmp -s "$expected" "$actual"; then
  printf 'component imports do not match the exact runtime allowlist\n' >&2
  diff -u "$expected" "$actual" >&2 || true
  exit 1
fi
