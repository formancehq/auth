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
