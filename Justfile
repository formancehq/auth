set dotenv-load

default:
  @just --list

pre-commit: generate tidy lint fctl-audit-check fctl-audit-test
pc: pre-commit

lint: && fctl-audit-lint
  @golangci-lint run --fix --build-tags it --timeout 5m

tidy: && fctl-audit-tidy
  @go mod tidy

generate:
  @go generate ./...

tests: && fctl-audit-test
  @go test -race -covermode=atomic \
    -coverprofile coverage.txt \
    -tags it \
    ./...

# plugins/fctl is a separate module (the fctl Auth plugin preparation), so the
# root recipes above do not reach it. These recipes cover it explicitly.

# Regenerate the committed Auth operation inventory artefacts.
fctl-audit:
  @cd plugins/fctl && ./scripts/with-fctl-sdk.sh go run ./cmd/specaudit

# Fail if the committed inventory artefacts no longer match openapi.yaml.
fctl-audit-check:
  @cd plugins/fctl && ./scripts/with-fctl-sdk.sh go run ./cmd/specaudit -check

fctl-audit-test:
  @cd plugins/fctl && coverage_profile="$(mktemp "${TMPDIR:-/tmp}/auth-fctl-coverage.XXXXXXXX")"; \
    trap 'rm -f "$coverage_profile"' EXIT; \
    ./scripts/with-fctl-sdk.sh go test -race -count=1 -covermode=atomic \
      -coverprofile "$coverage_profile" ./...; \
    ./scripts/check-coverage.sh "$coverage_profile"

fctl-audit-lint:
  @cd plugins/fctl && ./scripts/with-fctl-sdk.sh golangci-lint run --fix --timeout 5m

fctl-audit-tidy:
  @cd plugins/fctl && ./scripts/with-fctl-sdk.sh ./scripts/tidy-with-fctl-sdk.sh

fctl-audit-tidy-check:
  @cd plugins/fctl && ./scripts/with-fctl-sdk.sh ./scripts/tidy-with-fctl-sdk.sh --check

# Produce the deterministic portable component. Kept out of `pre-commit` and
# out of the default dev shell: it is the only gate needing the Rust authoring
# toolchain, and pulling that into every Go job makes unrelated CI runs fetch
# crates. It enters the pinned tools explicitly instead.
fctl-component-build:
  @nix shell .#componentize-go .#wasi-virt .#wasm-tools .#wasm-opt --command bash -c 'cd plugins/fctl && just build-component'

generate-client:
  @speakeasy generate sdk -s openapi.yaml -o ./pkg/client -l go

release-local:
  @goreleaser release --nightly --skip=publish --clean

release-ci:
  @goreleaser release --nightly --clean

release:
  @goreleaser release --clean
