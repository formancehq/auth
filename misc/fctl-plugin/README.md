# Auth fctl plugin

Profiles: **library** and **CLI**. This independent Go 1.26 module provides the
Auth command contract, declarative forms and HTTP execution for fctl. Its only
direct dependencies are the public `github.com/formancehq/fctl/pkg/pluginsdk`
module and `github.com/formancehq/auth/pkg/client`, the generated Auth client.
It does not depend on the fctl core or Auth server packages.

## Integration API

Import `github.com/formancehq/auth/misc/fctl-plugin` as `auth`:

```go
plugin := auth.NewVersion(authenticatedHTTPClient, "2.5.0-beta.1")
manifest, err := plugin.GetManifest(ctx)
response, err := plugin.Execute(ctx, pluginsdk.ExecuteRequest{
    CommandPath: []string{"auth", "clients", "create"},
    Endpoint:   "https://example.test/api/auth",
    Body:       json.RawMessage(`{"name":"automation"}`),
})
```

- `New(*http.Client) pluginsdk.Plugin` uses the development version `dev`.
- `NewVersion(*http.Client, string) pluginsdk.Plugin` puts the exact service
  version in the manifest. An empty version falls back to `dev`.
- A nil HTTP client supports offline metadata inspection. Execution requires
  an injected client; the plugin does not fall back to a global HTTP client.
- Each instance owns its version and returns fresh manifests. Manifest `name`
  and `service` are `auth`, the root targets `stack`, and the protocol version
  comes from `pluginsdk.ProtocolVersion`.

The host owns authentication, endpoint selection, file/stdin input, forms,
confirmation prompts and output rendering. Direct callers supply the JSON body
and `confirm: "true"` for destructive operations. Explicit false values and
empty collections in update patches clear options; omitted options are read
and preserved. The plugin validates patches before that read. Cancellation
before execution makes no HTTP request; cancellation during an update prevents
the subsequent write. Operations are not retried by the plugin.

The manifest retains all 12 commands: server info, OIDC discovery, client list,
show, create, update and delete, secret list, create and delete, and user list
and show. All creation forms and client, secret and user selectors remain
serializable SDK metadata. Responses preserve their original JSON bytes and
number precision; Auth errors return no response data. Secret creation returns
the one-time clear value; secret listing returns metadata only.

## Standalone executable

Run from this module directory:

```sh
GOWORK=off go build -o build/fctl-plugin-auth \
  -ldflags '-X main.serviceVersion=2.5.0-beta.1 -X main.revision=1' \
  ./cmd/fctl-plugin-auth
./build/fctl-plugin-auth --manifest
./build/fctl-plugin-auth --version
```

The service version must match the target Auth service exactly. Revision is a
separate positive integer for plugin-only changes; it is never appended to the
manifest version. Local builds default to service version `dev` and revision
`1`. Without metadata flags, the executable calls `transport.Serve` and uses
the host's HTTP broker. It has no independent credentials or terminal command
tree. Standard `flag` parsing replaces Cobra for these two metadata flags;
the executable has no service lifecycle requiring Fx. Owner: Auth maintainers.
Revisit this exception if independent user commands or listeners are added.

## Validation

```sh
GOWORK=off go test -race -cover ./...
GOWORK=off go vet ./...
```

The complete original Auth fixture suite is retained. Public consumer tests
cover exact version metadata, independent manifests, serialization, validation
before HTTP and cancellation. An executable fixture builds a versioned binary,
reads both metadata flags, starts it through the public SDK transport, and
checks the host authentication broker, gateway prefix, creation form, exact
JSON and rejected payloads. These are local fixtures, not live Auth validation.
The fctl loader, host UI and distribution pipeline are maintained separately.
Root-module `go test ./...` does not discover this nested module.

## Product builds

From the Auth repository root, `just test-fctl-plugin` tests this module with
race detection. The normal `just tests`, `just tidy` and `just lint` recipes
also include it. Build and inspect the exact service version with:

```sh
nix develop --impure --command just build-fctl-plugin 2.5.0-beta.1 1
nix develop --impure --command just fctl-plugin-manifest
nix develop --impure --command just package-fctl-plugin 2.5.0-beta.1 1
```

The snapshot recipe builds Linux, macOS and Windows executables for amd64 and
arm64, with archives and checksums under `build/fctl-plugin`. It skips
publication. The product GoReleaser configuration attaches the same six builds
to Auth releases, using the release service version and `PLUGIN_REVISION`.

fctl installs this executable with `plugins install --service auth --binary`
or resolves an exact-version OCI release with `plugins sync --service auth`.
Catalogue schema 1 entries use service `auth`, the manifest emitted by the
actual binary, the executable checksum and immutable OCI artifact digest.
Uploading public artifacts and advertising them in the official catalogue are
separate release operations; a snapshot does neither.

## Tagged release publication

After this workflow change is merged, the **next** Auth tag matching `v*.*.*`
starts `.github/workflows/releases.yml`. No existing release is republished.
For releases cut from a maintenance branch, cherry-pick the release tooling,
plugin module, GoReleaser configuration and Nix toolchain changes onto that
branch before tagging. Merging to another branch alone does not update its
release workflow.

Every work step runs through Nix and a root Just recipe. Before GoReleaser,
CI runs the plugin tests and real local OCI layout fixtures with race detection.
GoReleaser builds the server and the six plugin executables once. The publisher
consumes `dist/artifacts.json`, exports `--manifest` from that run's Linux/amd64
binary, and checks every binary before the first upload:

- Auth manifest name, service, root command and SDK protocol.
- Exact service version from the tag with the leading `v` removed.
- Separate positive `PLUGIN_REVISION` (currently `1` in the workflow).
- Auth executable entry point and embedded GOOS/GOARCH matching all six
  Linux, macOS and Windows amd64/arm64 combinations.
- Contained regular executable files, bounded sizes, and actual SHA-256 checksums.

Keep linker build metadata enabled: `-trimpath` would remove the linker flags
needed for this preflight. The publisher uses only the standard library and
public `pluginsdk`; it does not import fctl internals.

ORAS from the pinned Nix flake authenticates to GHCR with the job's
`GITHUB_TOKEN`, scoped to `packages: write`, through `--password-stdin`.
Credentials stay in a temporary Docker config removed when the recipe exits.
The publisher pushes to `ghcr.io/formancehq/fctl-plugin-auth`. Each artifact has
one raw executable layer (`application/vnd.formance.fctl.plugin.executable.v1`),
artifact type `application/vnd.formance.fctl.plugin.v1`, and an empty JSON config
(`application/vnd.oci.empty.v1+json`), using OCI image specification 1.1.

Only after all six pushes return valid immutable SHA-256 digests does the
publisher emit catalogue schemaVersion `1`. Each `releases` entry includes
`service`, `serviceVersion`, `revision`, `platform` (`os`, `arch`), `artifact`
(`registry`, `repository`, `digest`), `sha256`, and the native SDK `manifest`.
CI atomically replaces `dist/fctl-plugin-catalogue.json` and uploads it as an
Auth GitHub release asset. A preflight failure uploads nothing. An ORAS failure
emits no catalogue, though earlier successful platform uploads can remain.
Rerunning the tagged job reuses checksum-qualified tags and replaces the
catalogue asset only after a complete successful set.

To test artifact serialization without contacting a registry:

```sh
nix develop --impure --command just test-fctl-plugin test-fctl-plugin-publisher
```

The `fctl-plugin-publish` helper also accepts `--layout /absolute/fixture/path`,
`--manifest`, `--artifacts`, `--source-root`, `--service-version` and `--revision`.
For root GoReleaser builds, source-root is the repository root because artifact
paths include `dist/`; absolute contained artifact paths also work. Layout mode
still names GHCR in catalogue metadata, but creates no hosted download endpoint.

### First-publication GHCR setup

GitHub creates new GHCR packages privately by default. After the first successful
publication, an organization/package administrator must set
`formancehq/fctl-plugin-auth` to **Public** in GitHub package settings. For a
private Auth source repository, remove inherited repository permissions if
required and retain publishing access for the Auth Actions repository. If the
package already exists, grant this repository Actions access before release.
The workflow does not change package visibility or source repository visibility.
See [GitHub's Container registry documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

After that setup, use `just verify-fctl-plugin-anonymous` against the generated
catalogue (or a downloaded release asset) to fetch every artifact and verify
each executable checksum with an empty registry credential file. Run it before
advertising the entries in the official fctl catalogue. Release-asset publication
and public download availability are separate gates; the Auth workflow does not
change fctl's default catalogue or dependency pins.
