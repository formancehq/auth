# fctl Auth plugin

This module owns the portable Auth command integration for fctl. The component
currently exposes:

- nine Auth v1 commands for clients, client secrets, and users;
- one `auth.stack` client-credentials provider.

The provider accepts only a final host-validated credential slot. It forwards
that slot unchanged to the directional client-credentials broker, then binds
the returned opaque handle to the single requested operation. OIDC-only starts,
multi-operation flows, mismatched authority, and hosts without the directional
broker extension fail closed. See
[`docs/auth-provider-contract.md`](docs/auth-provider-contract.md).

Endpoint selection, credential bytes, OAuth endpoints, token acquisition,
authorization injection, retries, and transport remain host-owned. The command
adapter uses the generated public Auth client through `producthttp` and never
accepts a caller-supplied endpoint.

## Commands

The canonical surface is:

```text
clients list
clients create <name>
clients show <client-id>
clients update <client-id>
clients delete <client-id>
clients secrets create <client-id> <secret-name>
clients secrets delete <client-id> <secret-id>
users list
users show <user-id>
```

`clients secrets create` declares `/data/clear` as sensitive material. The host
may deliver it once to a human or adopt it into profile auth; the ordinary
plugin result contains only the secret's ID, name, metadata, and last digits.

The detailed OpenAPI and historical CLI correspondence remains in
[`docs/command-inventory.md`](docs/command-inventory.md).

Because the Auth API models `updateClient` as a full PUT replacement,
`clients update` first reads the existing client and merges only explicitly
provided flags before writing it back. Omitted fields are preserved; `--name`
is the explicit rename flag. The command therefore declares one `auth:read`
request followed by one `auth:write` request and a two-request host budget.

## Development

From this directory, enter the repository's pinned development shell first:

```sh
nix develop ../..
export FCTL_SDK_ROOT=/path/to/fctl-v2-poc
just test
just tidy-check
just build-component
```

The shell pins the same `componentize-go`, patched `wasi-virt`, `wasm-tools`,
and `wasm-opt` toolchain as fctl revision `e9b1395f`.

`FCTL_SDK_ROOT` names an explicit fctl source root. The wrapper validates the
SDK module's NAR content hash and canonical WIT hash against
`fctl-sdk.lock.json`. When the source includes Git metadata, it also requires
the locked commit and origin, then projects those exact committed SDK and WIT
paths before validation. Ignored or modified working-tree files therefore
cannot affect the command. The wrapper creates an ephemeral Go workspace, runs
the requested command against the validated SDK source, and removes the whole
projection afterward. No workstation path or Nix store path is tracked.

`just tidy` updates `go.mod` and `go.sum` from an isolated alternate modfile;
`just tidy-check` reports drift without changing them. The temporary modfile
contains the local SDK replacement only while `go mod tidy` runs, and that
replacement is removed before either file is compared or copied back.

`build-component` creates the component twice from the same staged source,
validates both artifacts, compares the component, WIT, imports and checksums,
and rejects an artifact larger than 16 MiB. It also publishes the generic
browser-cache input under `dist/auth/browser-input/`, containing exactly
`component.wasm` and `imports.txt`. `dist/` and `build/` are local outputs and
are not committed.

`just test` runs the race suite, component-entrypoint suite, fake-toolchain
artifact contract, and an aggregate statement-coverage gate with an enforced
minimum of 80%. The repository-root `just pre-commit` runs the same coverage
gate for this separate plugin module.

The declared Auth service major is `2`. That value is the published Stack v3.2
service-info authority, which binds Auth to image `v2.5.0`, and it agrees with
this repository's own `v2.5.0` release line. A host that attests major `1` is
rejected before any product request. External acceptance still requires a real
Stack service `/_info` receipt proving that major, plus CLI-host and
browser-host scenarios. Those external receipts are not produced by this
repository-local implementation.
