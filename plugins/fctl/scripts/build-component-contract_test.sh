#!/usr/bin/env bash
set -euo pipefail

readonly script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly test_root="$(mktemp -d "${TMPDIR:-/tmp}/auth-component-contract.XXXXXXXX")"
trap 'rm -rf "$test_root"' EXIT

plugin_root="$test_root/plugin"
mkdir -p "$plugin_root/scripts" "$plugin_root/entrypoints/auth" "$plugin_root/wit" "$test_root/bin"
cp "$script_root/build-component.sh" "$script_root/check-component-toolchain.sh" \
  "$script_root/go-component-build.sh" "$script_root/validate-imports.sh" "$plugin_root/scripts/"
cp "$script_root/../entrypoints/auth/implementation.go" "$plugin_root/entrypoints/auth/"
cp "$script_root/../wit/plugin.wit" "$plugin_root/wit/"
cp "$script_root/../main.go.in" "$plugin_root/"

cat > "$test_root/bin/componentize-go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == --version ]]; then printf 'componentize-go 0.4.1\n'; exit 0; fi
output=''; previous=''
for argument in "$@"; do
  [[ "$previous" == --output ]] && output="$argument"
  previous="$argument"
done
[[ -n "$output" ]] || exit 0
if [[ "$output" == */bindings ]]; then mkdir -p "$output"; else printf 'raw-component\n' > "$output"; fi
EOF
cat > "$test_root/bin/wasi-virt" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == --version ]]; then printf 'wasi-virt 0.2.0\n'; exit 0; fi
output=''; previous=''
for argument in "$@"; do [[ "$previous" == --out ]] && output="$argument"; previous="$argument"; done
printf 'virtualized-component\n' > "$output"
EOF
cat > "$test_root/bin/wasm-opt" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == --version ]] && { printf 'wasm-opt version 124\n'; exit 0; }
EOF
cat > "$test_root/bin/wasm-tools" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == --version ]]; then printf 'wasm-tools 1.239.0\n'; exit 0; fi
case "${1:-}" in
  strip)
    output=''; previous=''
    for argument in "$@"; do [[ "$previous" == --output ]] && output="$argument"; previous="$argument"; done
    cp "${@: -1}" "$output"
    ;;
  validate) ;;
  component)
    cat <<'WIT'
package example:auth;
world plugin {
  import wasi:clocks/wall-clock@0.2.12;
  import wasi:random/random@0.2.12;
  import wasi:cli/environment@0.2.12;
  import wasi:io/poll@0.2.12;
  import wasi:clocks/monotonic-clock@0.2.12;
  export formance:fctl-plugin/lifecycle@0.1.0;
}
WIT
    ;;
  *) printf 'unexpected wasm-tools arguments: %s\n' "$*" >&2; exit 97 ;;
esac
EOF
chmod +x "$test_root/bin/"*

PATH="$test_root/bin:$PATH" "$plugin_root/scripts/build-component.sh" >/dev/null
input="$plugin_root/dist/auth/browser-input"
[[ -f "$input/component.wasm" && -f "$input/imports.txt" ]] || {
  printf 'build did not publish the generic browser-cache input contract\n' >&2
  exit 1
}
files="$(cd "$input" && find . -type f -maxdepth 1 | LC_ALL=C sort | paste -sd' ' -)"
[[ "$files" == './component.wasm ./imports.txt' ]] || {
  printf 'browser-cache input contains unexpected files: %s\n' "$files" >&2
  exit 1
}
cmp "$input/component.wasm" "$plugin_root/dist/auth/auth.wasm"
cmp "$input/imports.txt" "$plugin_root/dist/auth/imports.txt"

printf 'fctl Auth component artifact contract: ok\n'
