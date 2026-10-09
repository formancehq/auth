set dotenv-load

default:
  @just --list

pre-commit: generate tidy lint
pc: pre-commit

lint:
  @golangci-lint run --fix --build-tags it --timeout 5m
  @cd misc/fctl-plugin && golangci-lint run --config .golangci.yml --fix --timeout 5m

tidy:
  @go mod tidy
  @cd misc/fctl-plugin && go mod tidy

generate:
  @go generate ./...

tests: test-fctl-plugin
  @go test -race -covermode=atomic \
    -coverprofile coverage.txt \
    -tags it \
    ./...

generate-client:
  @speakeasy generate sdk -s openapi.yaml -o ./pkg/client -l go

release-local:
  @goreleaser release --nightly --skip=publish --clean

release-ci:
  @goreleaser release --nightly --clean

release:
  @goreleaser release --clean

# Independent Auth CLI/library module; no Auth server dependencies.
test-fctl-plugin:
  @cd misc/fctl-plugin && go test -race ./...

build-fctl-plugin version="dev" revision="1":
  @cd misc/fctl-plugin && CGO_ENABLED=0 go build -ldflags '-X main.serviceVersion={{version}} -X main.revision={{revision}}' -o ../../build/fctl-plugin-auth ./cmd/fctl-plugin-auth

# Six platform executables and checksums, without publication.
package-fctl-plugin version="dev" revision="1":
  @AUTH_SERVICE_VERSION={{version}} PLUGIN_REVISION={{revision}} goreleaser release --config .goreleaser.fctl-plugin.yml --snapshot --clean --skip=publish

fctl-plugin-manifest:
  @./build/fctl-plugin-auth --manifest > ./build/fctl-plugin-manifest.json

# Release publication uses the native executable from this exact GoReleaser run.
publish-fctl-plugin-release:
  #!/usr/bin/env bash
  set -euo pipefail
  : "${GITHUB_REF_NAME:?release tag is required}"
  : "${GITHUB_TOKEN:?GitHub Actions token is required}"
  : "${GITHUB_ACTOR:?publishing actor is required}"
  [[ "$GITHUB_REF_NAME" == v* ]] || { echo 'Expected an Auth v-prefixed release tag' >&2; exit 1; }
  version="${GITHUB_REF_NAME#v}"
  revision="${PLUGIN_REVISION:-1}"
  native="$(jq -er '[.[] | select(.type == "Binary" and .extra.ID == "fctl-plugin-auth" and .goos == "linux" and .goarch == "amd64")] | if length == 1 then .[0].path else error("expected one native Auth plugin") end' dist/artifacts.json)"
  : "${GITHUB_REPOSITORY:?release repository is required}"
  release_root="$PWD"
  auth_dir="$(mktemp -d)"
  trap 'rm -rf "$auth_dir"; rm -f "$release_root/dist/fctl-plugin-catalogue.json.tmp" "$release_root/dist/fctl-plugin-manifest.json.tmp"' EXIT
  export DOCKER_CONFIG="$auth_dir"
  "$native" --manifest > dist/fctl-plugin-manifest.json.tmp
  printf '%s' "$GITHUB_TOKEN" | oras login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
  cd misc/fctl-plugin
  go run ./cmd/fctl-plugin-publish --manifest ../../dist/fctl-plugin-manifest.json.tmp --artifacts ../../dist/artifacts.json --source-root ../.. --service-version "$version" --revision "$revision" > ../../dist/fctl-plugin-catalogue.json.tmp
  cd ../..
  mv dist/fctl-plugin-catalogue.json.tmp dist/fctl-plugin-catalogue.json
  GH_TOKEN="$GITHUB_TOKEN" gh release upload "$GITHUB_REF_NAME" dist/fctl-plugin-catalogue.json --clobber --repo "$GITHUB_REPOSITORY"

# Real ORAS layout fixture; no registry authentication or writes.
test-fctl-plugin-publisher:
  @cd misc/fctl-plugin && go test -race -tags it ./internal/catalogue ./cmd/fctl-plugin-publish

upload-release-openapi:
  @gh release upload "$GITHUB_REF_NAME" ./openapi.yaml#openapi.yaml --repo "$GITHUB_REPOSITORY"

# Read-only check after an administrator enables public GHCR downloads.
verify-fctl-plugin-anonymous catalogue="dist/fctl-plugin-catalogue.json":
  #!/usr/bin/env bash
  set -euo pipefail
  catalogue_path="$(realpath '{{catalogue}}')"
  fixture="$(mktemp -d)"
  trap 'rm -rf "$fixture"' EXIT
  printf '{"auths":{}}' > "$fixture/config.json"
  jq -e '.schemaVersion == 1 and (.releases | length == 6)' "$catalogue_path" > /dev/null
  while IFS=$'\t' read -r registry repository digest checksum; do
    reference="${registry#https://}/$repository@$digest"
    oras pull --registry-config "$fixture/config.json" --output "$fixture/artifact" "$reference"
    printf '%s  %s\n' "$checksum" "$fixture/artifact/fctl-plugin-auth" | sha256sum --check
    rm -rf "$fixture/artifact"
  done < <(jq -r '.releases[] | [.artifact.registry, .artifact.repository, .artifact.digest, .sha256] | @tsv' "$catalogue_path")
