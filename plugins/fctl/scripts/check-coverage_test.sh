#!/usr/bin/env bash
set -euo pipefail

readonly script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly test_root="$(mktemp -d "${TMPDIR:-/tmp}/auth-fctl-coverage.XXXXXXXX")"
trap 'rm -rf "$test_root"' EXIT

mkdir -p "$test_root/bin"
cat > "$test_root/bin/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == tool && "$2" == cover ]]; then
  printf 'total:\t(statements)\t%s%%\n' "${FAKE_COVERAGE:?}"
  exit 0
fi
printf 'unexpected go arguments: %s\n' "$*" >&2
exit 97
EOF
chmod +x "$test_root/bin/go"
: > "$test_root/coverage.out"

output="$(PATH="$test_root/bin:$PATH" FAKE_COVERAGE=80.0 "$script_root/check-coverage.sh" "$test_root/coverage.out")"
[[ "$output" == 'fctl Auth plugin coverage: 80.0% (minimum 80%)' ]] || {
  printf 'unexpected passing output: %s\n' "$output" >&2
  exit 1
}

if PATH="$test_root/bin:$PATH" FAKE_COVERAGE=79.9 "$script_root/check-coverage.sh" "$test_root/coverage.out" \
  >"$test_root/stdout" 2>"$test_root/stderr"; then
  printf 'coverage below the threshold unexpectedly passed\n' >&2
  exit 1
fi
grep -F 'fctl Auth plugin coverage 79.9% is below the required 80%' "$test_root/stderr" >/dev/null

printf 'fctl Auth coverage gate: ok\n'
