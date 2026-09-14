#!/usr/bin/env bash
set -euo pipefail

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/auth-go-component-build.XXXXXXXX")"
trap 'rm -rf "$fixture_root"' EXIT
bin="$fixture_root/bin"
mkdir -p "$bin"

cat > "$bin/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
previous=""
for argument in "$@"; do
  if [[ "$previous" == '-o' ]]; then
    printf 'raw component\n' > "$argument"
  fi
  previous="$argument"
done
EOF

cat > "$bin/wasm-opt" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" > "$WASM_OPT_LOG"
printf 'optimized component\n' > "$5"
EOF
chmod +x "$bin/go" "$bin/wasm-opt"

output="$fixture_root/output.wasm"
WASM_OPT_LOG="$fixture_root/wasm-opt.log" PATH="$bin:$PATH" \
  "$script_root/go-component-build.sh" build -o "$output"

[[ "$(cat "$output")" == 'optimized component' ]]
[[ "$(cat "$fixture_root/wasm-opt.log")" == "-Oz --all-features $output --output $output.optimized" ]]

printf 'fctl Auth Go component build wrapper: ok\n'
