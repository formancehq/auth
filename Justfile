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
