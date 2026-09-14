package audit

import "sort"

// Blocker is something unproven that prevents an operation, or the whole
// preparation, from being admitted into a plugin catalogue.
//
// A blocker is not an exclusion. Exclusions (exclusions.go) are deliberate
// scoping decisions about operations that are fully understood. A blocker
// records that a fact required for admission could not be established here.
type Blocker struct {
	ID string `json:"id"`
	// OperationIDs are the operations the blocker applies to. Empty means the
	// blocker is module-wide and applies to every operation.
	OperationIDs []string `json:"operationIds"`
	// Statement is what is not proven.
	Statement string `json:"statement"`
	// Evidence is the reproducible observation that establishes the blocker.
	Evidence string `json:"evidence"`
	// Clears is what would have to happen for the blocker to lift.
	Clears string `json:"clears"`
}

// Blockers is the current machine-readable catalogue-admission state. The nine
// implemented command operations have no remaining admission blocker. Live
// Stack receipts and component/host execution are external acceptance gates,
// not reasons to mark the implemented catalogue as inadmissible.
var Blockers = []Blocker{}

// Divergence is a recorded inconsistency in, or limitation of, the source
// document. Divergences are separated from blockers because they do not by
// themselves prevent admission: they are facts a later implementation must
// handle, not missing proof.
type Divergence struct {
	ID string `json:"id"`
	// OperationIDs are the operations affected. Empty means document-wide.
	OperationIDs []string `json:"operationIds"`
	// Statement is the divergence.
	Statement string `json:"statement"`
	// Evidence is the reproducible observation.
	Evidence string `json:"evidence"`
	// Impact is what a later implementation has to do about it.
	Impact string `json:"impact"`
}

// Divergences are the recorded spec-versus-server and internal document
// divergences.
var Divergences = []Divergence{
	{
		ID:           "no-pagination",
		OperationIDs: []string{"listClients", "listUsers"},
		Statement: "Neither collection operation offers pagination. Both return an " +
			"unbounded array, so response size is governed only by how many " +
			"objects the stack holds.",
		Evidence: "listClients (GET /clients) and listUsers (GET /users) declare no " +
			"parameters at all. ListClientsResponse.data and ListUsersResponse.data " +
			"are plain arrays of Client and User with no cursor, page-size, total, " +
			"or next-page field. Operation.Paginated() is false for every " +
			"operation in the document; the golden report pins that.",
		Impact: "The plugin cannot offer paging, streaming, or a page-size flag for " +
			"these operations without a product change, and must not present a " +
			"synthetic cursor. A host rendering these results should expect an " +
			"unbounded payload.",
	},
	{
		ID: "localhost-server",
		Statement: "The document's only declared server is a local development " +
			"address, not the stack route the plugin will actually be bound to.",
		Evidence: "openapi.yaml declares `servers: [{url: http://localhost:8080/}]`, " +
			"whereas fctl-v2 binds the Auth service to the selected stack " +
			"gateway route /api/auth (plan line 557).",
		Impact: "Endpoint selection is host-owned and the document's server list must " +
			"be ignored by the plugin. Only the paths are usable; the base URL is " +
			"not. This is consistent with Task 9 forbidding the auth facet from " +
			"receiving endpoint bytes at all.",
	},
	{
		ID:           "create-secret-success-code",
		OperationIDs: []string{"createSecret", "createClient"},
		Statement: "The two creating operations disagree on their success code: " +
			"createClient returns 201 while createSecret returns 200.",
		Evidence: "openapi.yaml:72 declares '201' for createSecret's sibling " +
			"createClient (POST /clients), and openapi.yaml:168 declares '200' " +
			"for createSecret (POST /clients/{clientId}/secrets).",
		Impact: "A plugin adapter must key success on the per-operation code recorded " +
			"here rather than on a family-wide rule for POST, and must not " +
			"normalise one to the other.",
	},
	{
		ID: "no-error-responses",
		Statement: "No operation declares any 4xx or 5xx response, so no error " +
			"status code or error body shape is proven for any operation.",
		Evidence: "The document contains zero response keys beginning with 4 or 5 " +
			"and no error schema. Error handling is delegated wholesale to the " +
			"generator via `x-speakeasy-errors: {statusCodes: [default]}`.",
		Impact: "Error mapping, retry classification, and the destructive-operation " +
			"not-found case cannot be derived from the document. The adapter uses " +
			"the generated client's behavior, but live-service evidence remains an " +
			"external acceptance requirement.",
	},
	{
		ID: "paths-vendor-extension",
		Statement: "A vendor extension is placed inside the `paths` object as a " +
			"sibling of the path items, where the OpenAPI 3.0 schema expects only " +
			"path items and `x-` extensions at that level are generator-specific.",
		Evidence: "openapi.yaml:8-11 places `x-speakeasy-errors` under `paths:` " +
			"before the first real path. A naive loader that decodes every key " +
			"under `paths` as a path item would silently treat it as a path with " +
			"no operations.",
		Impact: "The loader in spec.go skips exactly this one known extension key and " +
			"errors on any other non-path key, so a future document change cannot " +
			"be absorbed unnoticed.",
	},
	{
		ID: "client-module-go-version",
		Statement: "The generated client module declares a Go version far below the " +
			"product module's, and its go.mod is inconsistently indented.",
		Evidence: "pkg/client/go.mod declares `go 1.20` while the root go.mod " +
			"declares `go 1.26.0`. The client's require block mixes a leading tab " +
			"on the first entry with four-space indentation on the other two, and " +
			"the file begins with a blank line.",
		Impact: "The plugin module compiles and tests its generated-client adapter " +
			"with its own dependency sums. The nested module formatting and version " +
			"remain upstream packaging provenance, not a catalogue-admission blocker.",
	},
	{
		ID: "empty-scheme-scopes",
		Statement: "The OAuth2 scheme's scopes map is empty even though every " +
			"operation requires exactly auth:read or auth:write.",
		Evidence: "openapi.yaml declares `scopes: { }` for the Authorization " +
			"client-credentials flow, while all 11 operation security requirements " +
			"name exactly one of auth:read and auth:write.",
		Impact: "The catalogue pins and the host enforces the exact per-operation " +
			"scope sets. The empty scheme-wide map remains a source-document " +
			"limitation to cross-check if upstream begins enumerating scopes.",
	},
}

// BlockersFor returns the blocker IDs that apply to the operation, sorted. A
// blocker with no OperationIDs is module-wide and applies to every operation.
func BlockersFor(operationID string) []string {
	out := make([]string, 0)
	for _, b := range Blockers {
		if len(b.OperationIDs) == 0 {
			out = append(out, b.ID)
			continue
		}
		for _, id := range b.OperationIDs {
			if id == operationID {
				out = append(out, b.ID)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// DivergencesFor returns the divergence IDs that apply to the operation,
// sorted. A divergence with no OperationIDs is document-wide and is not
// attributed to individual operations, so it is not returned here.
func DivergencesFor(operationID string) []string {
	var out []string
	for _, d := range Divergences {
		for _, id := range d.OperationIDs {
			if id == operationID {
				out = append(out, d.ID)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// ModuleWideBlockers returns the blockers that apply to every operation,
// sorted by ID.
func ModuleWideBlockers() []Blocker {
	var out []Blocker
	for _, b := range Blockers {
		if len(b.OperationIDs) == 0 {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
