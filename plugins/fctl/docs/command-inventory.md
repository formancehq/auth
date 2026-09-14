# fctl Auth plugin — command inventory and compatibility record

Hand-written source of truth for the Auth operation inventory and compatibility
evidence. Derived tables live in
[`operations.generated.md`](operations.generated.md); regenerate them with
`just fctl-audit`. Where this document quotes a count, the count is asserted
against the generated report by `audit/documented_test.go`, so the two cannot
drift.

## Status

This directory contains a nine-command catalogue, a generated-client adapter
over the host-owned `producthttp` boundary, and a portable component exposing
both command and `auth.stack` facets. The catalogue retains the operation
mapping, scope sets, risks, and exclusions established by this inventory.

Repository-local tests do not replace external acceptance. In particular, the
declared service major `2` still needs a real Stack `/_info` receipt. The
client-credentials contract is documented in
[`auth-provider-contract.md`](auth-provider-contract.md). Real CLI-host and
browser-host execution remains external acceptance evidence.

## Pinned revisions

| Tree | Revision | Role |
|---|---|---|
| `formancehq/auth` | `e4979fe9a52de6601d60d45d6c695db25f391f7a` | Product source; `openapi.yaml` is the authoritative contract |
| `formancehq/fctl` (v3) | `693c58e27865f83332e6c3199d61fed81b742f41` | Legacy executable command baseline |
| `fctl-v2` | `8de8c4539ea6664351762dd8dd0e865292e3f216` | Programme plan and parity baseline |

## Source provenance

The pinned `openapi.yaml` remains the source of operation semantics. The
implemented adapter also imports the real generated Auth client, and its nine
method mappings and request/response types are now proven by compilation and
adapter tests in this plugin module.

The initial preparation audit recorded a separate upstream packaging issue:
`pkg/client` did not compile from its own committed module files at the pinned
Auth revision.

`pkg/client/go.sum` holds exactly 3 lines for the 3 modules
`pkg/client/go.mod` requires, and all 3 are `/go.mod` hashes. Not one module
has its zip `h1:` hash, so no dependency can be extracted:

```console
$ cd pkg/client && go build ./...
v1.go:9:2: missing go.sum entry for module providing package
github.com/cenkalti/backoff/v4 (imported by github.com/formancehq/auth/pkg/client)
```

With `GOPROXY=off` the same build reports `module lookup disabled by
GOPROXY=off`. A networked `go build` will silently append hashes to `go.sum` as
it resolves, so this must be verified against a clean checkout.

The earlier fctl-v2 generated-client source audit
(`docs/validation/task4a-generated-client-source-audit.md`) already recorded
Auth as `Blocked: incomplete committed client go.sum`, at revision
`0821349d95258c9651c1d468978017d07d8c1199`. This re-verification at
`e4979fe9a52de6601d60d45d6c695db25f391f7a` preserved that observation. This
is historical provenance, not current plugin admission state: the plugin
module carries complete dependency sums and its generated-client adapter
compiles and is tested. Repairing the nested upstream module remains a product
packaging concern, but `client-go-sum` is no longer a current blocker here.

## Surface

The document declares **11 operations over 8 paths**, all tagged `auth.v1`,
and marks **0** deprecated.

Of those, **9 are included** in the command facet and **2 are excluded**. The
9 included operations are exactly the 9 the legacy CLI reached, so this
inventory proposes no addition beyond historical parity and no removal from it.

### Functional groups

Four families, frozen in `audit/classify.go`. An operation a future document
adds fails classification loudly rather than landing in a catch-all.

| Family | Operations | Facet |
|---|---|---|
| `clients` | `listClients`, `createClient`, `readClient`, `updateClient`, `deleteClient` | command |
| `secrets` | `createSecret`, `deleteSecret` | command |
| `users` | `listUsers`, `readUser` | command |
| `discovery` | `getOIDCWellKnowns`, `getServerInfo` | excluded |

## Baseline correspondence

The fctl-v2 parity baseline (`docs/compatibility/README.md`) records Auth as 9
historical executable operations over 11 historical CLI paths, 4 reads and 5
writes. This preparation reproduces all four numbers from the current document
plus the pinned legacy tree rather than restating them;
`TestIncludedMatchesFctlV2Baseline` is that assertion.

The count is 11 paths over 9 operations because the `users` subtree is mounted
twice: below `auth` (`cmd/auth/root.go:16`) and again below `auth clients`
(`cmd/auth/clients/root.go:22`). The two extra paths are therefore
`auth clients users list` and `auth clients users show <user-id>`. They are
recorded as duplicate mounts, not as separate operations. Task 9 states legacy
alternate paths need not remain executable, so a later implementation may
expose the canonical 9 and drop the 2 duplicates without a parity loss — but
the duplication must be a recorded decision, not an oversight.

Every included operation has legacy precedent; **0** included operations lack
it. The per-operation mapping, with aliases, argument contracts, and the source
line proving each declaration, is in
[`operations.generated.md`](operations.generated.md).

## Authorisation

All 11 operations declare a security block, so none is a no-auth operation.
The document uses a single `Authorization` OAuth2 client-credentials scheme
with exactly one requirement object per operation, and only two scopes exist:
`auth:read` (**6** operations) and `auth:write` (**5** operations).

Each per-operation scope set is an exact single-element set. That matters for
RFC 0014, which requires an exact-set check at every dispatch: a subset or
superset is a failure, not an approximation. `TestExactScopes` pins all 11.

The scheme's own `scopes` map is empty (`{ }`) while every operation references
concrete scopes through it. This is recorded as divergence
`empty-scheme-scopes`. It does not block the catalogue: the plugin pins the
exact per-operation sets and the host validates them at dispatch. A populated
upstream scheme map would provide an additional cross-check.

## Human table rendering

Seven of the nine commands declare a `RenderHints.Table`: an explicit, ordered,
stable column list for the human view only. The column set is a deliberate
subset; `PublicOutputSchema` is untouched and `--output json` and
`--output yaml` keep returning the complete public result.

| Command | Columns, in order |
|---|---|
| `auth clients list` | ID, Name, Public, Trusted |
| `auth clients create` | ID, Name, Public, Trusted |
| `auth clients show` | ID, Name, Public, Trusted |
| `auth clients update` | ID, Name, Public, Trusted |
| `auth clients secrets create` | ID, Name, Last Digits |
| `auth users list` | ID, Subject, Email |
| `auth users show` | ID, Subject, Email |

### Header casing convention

Headers are **Title Case**, derived from the field: split the last dotted
segment at camelCase boundaries, upper-case a known initialism, Title Case
every other word. So `id` is `ID`, `lastDigits` is `Last Digits`.

This is a recorded decision, not an inference. Both sources that actually spell
a header agree on Title Case:

- the shipped CLI. `fctl` v3 at pinned revision
  `693c58e27865f83332e6c3199d61fed81b742f41` prints
  `ID  Name  Description  Public  Permissions` for `auth clients list`
  (`cmd/auth/clients/list.go:105`) and `ID  Subject  Email` for
  `auth users list` (`cmd/auth/users/list.go:97`). All three user columns here
  are byte-identical to that header row;
- the fctl SDK's own `RenderHints` examples —
  `{Header: "Display Name"}`, `{Header: "Tags"}`, `{Header: "Phase"}`
  (`pkg/plugin/sdk/contracts_v2_test.go`), `{Header: "Name"}`
  (`cmd/fctl/generic_test.go`, `pkg/plugin/sdk/validation_test.go`), and
  `{Header: "ID"}` (`protocol/componentbridgev1alpha1/codec_test.go`).

The fctl-v2 host's `strings.ToUpper` in `renderTable`
(`internal/app/presentation.go`) is not a counter-example: it upper-cases keys
*derived from a result that supplied no layout*, and never touches an authored
`Header`. It is the fallback the hints exist to replace.

`TestTableHeadersFollowTheDocumentedTitleCaseConvention` derives the expected
header from the field rather than comparing against a second hand-written list,
so a new column cannot introduce a different casing.

`TableColumn.Field` is a dotted path in the SDK's own examples
(`metadata.name`, `spec.displayName`, `status.phase`). Auth declares only
top-level fields today, but the traversal the tests check with is generic and
collection-transparent, and is proven directly by
`TestFieldPathTraversalResolvesDottedPathsGenerically`.

### The compact-detail trade-off

`show`, `create` and `update` are hinted on purpose, and this costs something:
under a host that honours the hints, those commands render a one-row table of
the columns above instead of listing every property of the object. A reader of
`auth clients show` therefore sees four scalars, not ten properties.

That is the intended trade-off. The table is a **compact scalar summary**:
identity first, then the two booleans that decide how a client authenticates
and consents. Long and container-valued properties are dropped from the human
view because a cell cannot hold them without printing raw JSON back at the
reader, which is exactly what makes an unhinted table unreadable.

**Nothing is lost.** Every dropped property stays in the emitted public result
and remains accepted by the permissive `PublicOutputSchema`, so `--output json`
and `--output yaml` keep the complete structured output. The detail view a
script needs is the structured one; the table is for a human scanning a
terminal.

`TestTablesAreACompactScalarSummaryWhileStructuredOutputStaysExhaustive`
records this per command and fails three ways: if a column resolves to a
container, if the set of omitted properties stops matching the recorded
decision, or if an omitted property is no longer present in the emitted public
result. `TestPublicOutputSchemaStaysTheExhaustiveStructuredContract` pins the
schema bytes of all nine commands, so narrowing the contract to the table
columns — or erasing it — fails in this package rather than only in the
component descriptor test.

Deliberately excluded from every table, and asserted by
`TestTableColumnsExcludeSecretsNestedAndLongValues`:

- `clear` — display-once credential material, already absent from the public
  `createSecret` projection. `TestCreateSecretTableKeepsTheDisplayOnceBoundary`
  re-proves both the absence and the retained sensitive-output declaration.
- `metadata`, `secrets`, `redirectUris`, `postLogoutRedirectUris`, `scopes` —
  containers a cell cannot hold without printing raw JSON back at the reader.
- `description` — unbounded free text.

### Field evidence

Every `Field` names a scalar property the emitted public result really carries.
This is not asserted from a hand-written list:
`TestTableColumnFieldsAreCoherentWithTheRealPublicResult` executes each command
against the widest documented fixture and resolves every column against the
adapter's own emitted envelope. A field is backed when the emitted result
resolves it to a scalar, or when the public output schema declares it; a
command with **no** public output schema is itself a violation, so erasing the
contract cannot make the check pass.

`TestFixturesMatchTheGeneratedAuthClientTypes` pins those fixtures to the JSON
tags of every generated type they encode — `components.Client`,
`components.ClientSecret`, `components.User` and `components.Secret` — so a
fixture cannot drift from the type the adapter decodes into.
`TestFieldCoherenceFailsClosedOnAMissingOrUnbackedField` drives the coherence
check directly with absent, narrowed and unbacked inputs, so the check is
proven non-vacuous on every run rather than only under a permissive schema.
Column identity and order are pinned by
`TestCatalogueDeclaresTheExactOrderedTableColumns`.

### Commands left without a table hint

`deleteClient` and `deleteSecret` return **204 with no declared response
schema**, and the adapter emits a canonical empty object for both. There is no
real property to put in a column, so `auth clients delete` and
`auth clients secrets delete` declare **no** table hint rather than an invented
one. `TestCommandsWithoutRenderableResultsDeclareNoTableHint` fails if either
gains one, and also fails on a command this test classifies neither way, so a
tenth command cannot slip past unexamined.

The fctl host at pinned revision `e9b1395f46f3100b381dbe00f5213de28e6df0e1`
derives table columns from the result itself and does not yet read these hints
(`internal/app/presentation.go`). The hints are therefore a declared, tested
catalogue contract whose human effect — including the compact-detail trade-off
above — remains an external acceptance gate.

## Risks

### Display-once credential material

`createSecret` is the only operation returning a credential in clear text. It
is at JSON Pointer `/data/clear` in its 200 `CreateSecretResponse`.

This is proven, not assumed: `CreateSecretResponse.properties.data` is a `$ref`
to `Secret`, and `Secret`'s `allOf` member declares `clear` as a **required**
property alongside `id` and `lastDigits`. Being required, it is always present
on success. `Secret`'s own description states the full value is returned only
at creation and cannot be retrieved again.

Task 9 requires this operation to remain exposed in CLI, notebook, MCP, and
WebMCP as a sensitive mutation — it is not an exclusion — with `display_once`
and `profile_auth` delivery, and with model-visible results limited to ID,
name, last digits, receipt, and adoption status. The catalogue declares the
pointer and delivery policy, the adapter strips clear material from its
ordinary result, and the host owns extraction and delivery. Live validation of
both delivery modes remains an external acceptance gate.

### Destructive operations

`deleteClient` and `deleteSecret` both return **204 with no declared response
schema**. A host therefore gets no response evidence of what was removed, and
cannot echo the deleted object back to the user. Combined with
`no-error-responses` below, the not-found case is also unproven.

### Idempotence

Derived from method semantics only, and only that. `createClient` and
`createSecret` are POSTs and the document declares no idempotency key header or
request field anywhere, so a retried call creates a second object — for
`createSecret`, a second live credential. `updateClient` is a PUT full
replacement; the plugin performs a bounded `readClient` first and merges only
the explicitly supplied flags so omitted fields are not reset. Both deletes are
DELETEs, so all three mutations are idempotent by method. Whether the server
honours those semantics is unverified; no server was contacted.

### Pagination and streaming

Neither collection operation offers pagination. `listClients` and `listUsers`
declare **no parameters at all**, and both return a plain unbounded `data`
array with no cursor, page-size, total, or next-page field. **0** operations in
the document offer pagination.

The plugin cannot offer paging, streaming, or a page-size flag for these
operations without a product change, and must not present a synthetic cursor.
A host rendering these results should expect an unbounded payload.
Divergence `no-pagination`, asserted by `TestNoPagination` so that adding
pagination later fails the build rather than leaving the divergence stale.

### Confirmation

All 5 legacy mutation paths gated execution behind `fctl.WithConfirmFlag` plus
`fctl.CheckStackApprobation`, and no read path did.

That is recorded as an observation about the pinned tree, not a rule imposed on
it. The risk class in `audit/classify.go` is derived from the document alone
and never reads the confirmation flag, so
`TestRiskAgreesWithLegacyConfirmation` cross-checks two independently sourced
facts. A disagreement means one of the two was misread.

## Exclusions

Both exclusions are scoping decisions about fully understood operations, and
neither is a deprecation — the document deprecates nothing. Neither excluded
operation was reached by any legacy fctl `auth` command, so neither exclusion
is a parity regression; `TestExclusionsAreJustified` enforces that.

**`getServerInfo` (`GET /_info`)** — Service version and capability discovery
belongs to the fctl host, not to a product plugin. The programme binds Auth to
the stack gateway route `/api/auth` and treats `/_info` as the public
host-owned response (plan line 557); Task 9 requires the product major to come
from that host response. A plugin calling `/_info` itself would be attesting
its own version.

**`getOIDCWellKnowns` (`GET /.well-known/openid-configuration`)** — OIDC
provider metadata is consumed by the host authentication broker during the
OAuth2 client-credentials exchange. The public directional facet exposes only
`AuthorizeClientCredentials` and `BindCredential` to this provider. Credential
generation checks, token persistence, and capability-scoped invalidation remain
host-owned, and the provider receives no client ID, client secret, endpoint,
access token, or Authorization bytes. The operation also declares no response
content schema, so it exposes no typed result a command could render.

## Divergences

Facts a later implementation must handle. Distinct from blockers: these are
known, not missing.

| ID | Statement |
|---|---|
| `no-pagination` | Both collection operations return unbounded arrays with no pagination parameters. |
| `localhost-server` | The only declared server is `http://localhost:8080/`, not the stack route `/api/auth`. Endpoint selection is host-owned; the document's base URL must be ignored. |
| `create-secret-success-code` | `createClient` returns 201 but `createSecret` returns 200. An adapter must key success per operation, not by a family-wide POST rule. |
| `no-error-responses` | No operation declares any 4xx or 5xx response and no error schema exists; error handling is delegated wholesale to the generator via `x-speakeasy-errors`. Error mapping, retry classification, and not-found handling cannot be derived from the document. |
| `paths-vendor-extension` | `x-speakeasy-errors` sits inside `paths` as a sibling of the path items. The loader skips this one known key and errors on any other non-path key. |
| `client-module-go-version` | `pkg/client/go.mod` declares `go 1.20` against the root module's `go 1.26.0`, with inconsistent indentation. The plugin adapter compiles through its own module; this remains upstream packaging provenance. |
| `empty-scheme-scopes` | The OAuth2 scheme map is empty although every operation requires exactly `auth:read` or `auth:write`; the catalogue pins and the host enforces those exact per-operation sets. |

## Current admission blockers

There are **0 current admission blockers**. Every one of the 9 included
operations has a proven method mapping, path, exact scope set, parameter
handling, request body where applicable, success handling, and risk metadata,
backed by the compiling generated-client adapter and its tests.

External acceptance gaps below remain deliberately separate from catalogue
admission. They do not convert local implementation evidence into a component,
installation, browser-host, or live-service receipt.

### Historical preparation blockers

The preparation audit originally used these labels before the adapter and
catalogue existed. They are retained only as provenance:

| Historical ID | Earlier observation | Current disposition |
|---|---|---|
| `client-go-sum` | The nested generated-client module lacked dependency zip hashes. | Cleared for this plugin by its compiling, tested generated-client adapter and complete plugin-module sums; the nested upstream packaging issue remains provenance. |
| `no-live-info-major` | No live host-owned Auth product-major receipt existed. | Reclassified as external acceptance; the catalogue declares major 2, matching the published Stack v3.2 service-info authority and this repository's `v2.5.0` release line, and still requires a live `/_info` receipt before release. |
| `no-live-service` | No real Stack service behavior had been exercised. | Reclassified as external acceptance; local adapter tests do not replace live CLI/browser scenarios. |
| `empty-scheme-scopes` | The OAuth2 scheme map did not enumerate the operation scope names. | Reclassified as a source divergence; exact per-operation scope sets are pinned and host-validated. |

## External acceptance gaps

The catalogue, adapter, command descriptor, lifecycle entry point, and local
deterministic build recipe exist. Release acceptance still requires:

- an attested Auth product major from the host-owned public `/_info` probe;
- one successful two-lane component build with its size, digest, WIT, and
  imports receipts;
- OCI installation and command execution in both the CLI and browser hosts;
- a real Stack service run covering one read, one mutation, and both sensitive
  secret delivery modes;
- a real `auth.stack` client-credentials exchange in both hosts, proving the
  contract in [`auth-provider-contract.md`](auth-provider-contract.md);
- a parity report against the attested major with every applicable operation
  covered and no unexplained path gap.

## Layout

| Path | Role |
|---|---|
| `docs/command-inventory.md` | This document. Hand-written reasoning, evidence, risks, blockers, gates. |
| `docs/operations.generated.md` | Generated tables: totals, per-family operations, parameters, baseline mapping, exclusions, blockers, divergences. |
| `audit/spec.go` | Reads `openapi.yaml` into typed operations. No inference; rejects malformed documents. |
| `audit/baseline.go` | The pinned legacy fctl `auth` baseline with per-command source lines. |
| `audit/classify.go` | Frozen family table, risk derivation, idempotence, sensitive pointer. |
| `audit/exclusions.go` | The 2 exclusions with owner, reason, and evidence. |
| `audit/blockers.go` | Current admission blockers (currently zero) and 7 divergences. |
| `audit/report.go` | Assembles the report and derives every quoted count. |
| `audit/markdown.go` | Renders the generated document. |
| `audit/testdata/report.json` | Golden report; the determinism gate. |
| `cmd/specaudit` | Regenerates or verifies the two committed artefacts. |

## Commands

From the repository root inside `nix develop`:

```sh
just fctl-audit         # regenerate the committed inventory artefacts
just fctl-audit-check   # fail if they no longer match openapi.yaml
just fctl-audit-test    # run the module's tests with race and coverage
```

Or from `plugins/fctl`:

```sh
go test ./...
```

## What must not be inferred from this directory

- The nine included operations are implemented in the catalogue, but that does
  not itself prove a component build, OCI installation, dual-host execution, or
  live-service behavior.
- Generated-client method names are compilation- and test-backed; the pinned
  OpenAPI document remains the source for operation semantics.
- Exact per-operation authorisation scopes are enforced. The empty scheme-wide
  map remains a source limitation, not additional authorization evidence.
- The document's declared server is not an endpoint. Endpoint selection, auth
  attachment, and transport remain host-owned.
- No component build, OCI installation, dual-host behavior, or live Stack
  receipt is claimed by this inventory.
