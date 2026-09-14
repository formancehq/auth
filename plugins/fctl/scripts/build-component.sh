#!/usr/bin/env bash
set -euo pipefail
readonly component_limit_bytes=$((16 * 1024 * 1024))
plugin_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
entrypoint="$plugin_root/entrypoints/auth/implementation.go"
module_path="github.com/formancehq/auth/plugins/fctl"
for tool in cmp go; do command -v "$tool" >/dev/null || { printf 'required build tool is unavailable: %s\n' "$tool" >&2; exit 1; }; done
"$plugin_root/scripts/check-component-toolchain.sh"
export GOFLAGS="${GOFLAGS:-} -trimpath -tags=fctl_component_guest"
staging="$plugin_root/build/component-staging"
rm -rf "$staging"; mkdir -p "$staging"; trap 'rm -rf "$staging"' EXIT
build_lane() {
  local lane="$1"
  local lane_root="$staging/source"
  local result="$staging/result-$lane"
  local bindings_path="$module_path/build/component-staging/source/bindings"
  rm -rf "$lane_root"; mkdir -p "$lane_root/bindings/export_formance_fctl_plugin_lifecycle" "$result"
  cp "$entrypoint" "$lane_root/bindings/export_formance_fctl_plugin_lifecycle/implementation.go"
  componentize-go --ignore-toml-files -d "$plugin_root/wit" -w plugin bindings --format --pkg-name "$bindings_path" --output "$lane_root/bindings"
  sed "s|github.com/formancehq/auth/plugins/fctl/bindings|$bindings_path|g" "$plugin_root/main.go.in" > "$lane_root/main.go"
  (cd "$lane_root"; componentize-go --ignore-toml-files -d "$plugin_root/wit" -w plugin build --go "$plugin_root/scripts/go-component-build.sh" --output auth.raw.wasm; wasi-virt --allow-clocks --allow-random --allow-env --stdio=ignore --out auth.wasm auth.raw.wasm; wasm-tools strip --all --output auth.stripped.wasm auth.wasm; mv auth.stripped.wasm auth.wasm; wasm-tools validate auth.wasm; wasm-tools component wit auth.wasm > auth.wit; sed -n -E 's/^[[:space:]]*import ([^[:space:];]+).*/\1/p' auth.wit > imports.txt; "$plugin_root/scripts/validate-imports.sh" imports.txt; size="$(wc -c < auth.wasm | tr -d ' ')"; [[ "$size" -le "$component_limit_bytes" ]] || { printf 'component exceeds limit: %s\n' "$size" >&2; exit 1; }; shasum -a 256 auth.wasm auth.wit imports.txt > artifact.sha256)
  cp "$lane_root"/{auth.wasm,auth.wit,imports.txt,artifact.sha256} "$result/"
}
build_lane one; build_lane two
for artifact in auth.wasm auth.wit imports.txt artifact.sha256; do cmp "$staging/result-one/$artifact" "$staging/result-two/$artifact"; done
destination="$plugin_root/dist/auth"; rm -rf "$destination"; mkdir -p "$destination/browser-input"; install -m 0444 "$staging/result-one"/* "$destination/"; install -m 0444 "$staging/result-one/auth.wasm" "$destination/browser-input/component.wasm"; install -m 0444 "$staging/result-one/imports.txt" "$destination/browser-input/imports.txt"; printf '%s\n' "$destination/auth.wasm"
