package audit

import "sort"

// Exclusion records an operation the document declares that the fctl Auth
// command facet deliberately does not expose, with the reason it is excluded.
//
// An exclusion is a scoping decision, not a blocker: the operation is
// understood and intentionally out of scope. Blockers, in blockers.go, are the
// opposite — operations whose admission is prevented by something unproven.
type Exclusion struct {
	OperationID string `json:"operationId"`
	// Reason is why the command facet does not expose the operation.
	Reason string `json:"reason"`
	// Owner is the component that does own the operation instead.
	Owner string `json:"owner"`
	// Evidence is what proves the exclusion is correct.
	Evidence string `json:"evidence"`
}

// Exclusions are the two discovery operations the command facet does not
// expose. Both are host-owned, and neither has a legacy fctl `auth` command.
//
// Neither exclusion is a deprecation: the document marks no operation
// deprecated, which report.Build asserts.
var Exclusions = []Exclusion{
	{
		OperationID: "getServerInfo",
		Reason: "Service version and capability discovery is owned by the fctl " +
			"host, not by a product plugin. The programme requires the product " +
			"major to come from the host's own /_info call so one host response " +
			"drives every plugin's supported-major check; a plugin that called " +
			"/_info itself would be attesting its own version.",
		Owner: "fctl host target resolution",
		Evidence: "fctl-v2 docs/superpowers/plans/2026-08-26-fctl-complete-program.md:557 " +
			"binds the Auth service to the stack gateway route /api/auth and " +
			"describes /_info as the public host-owned response; Task 9 " +
			"(line 2276) requires the major to be attested by that host response. " +
			"No legacy fctl auth command dispatches getServerInfo.",
	},
	{
		OperationID: "getOIDCWellKnowns",
		Reason: "OIDC provider metadata is consumed by the host authentication " +
			"broker while it performs the OAuth2 client-credentials exchange. " +
			"The public directional client-credentials facet exposes only " +
			"AuthorizeClientCredentials and BindCredential to this provider. " +
			"Endpoint discovery, credential generation checks, token persistence, " +
			"and capability-scoped invalidation remain host-owned, so the plugin " +
			"cannot be the party that fetches provider metadata.",
		Owner: "fctl host authentication broker",
		Evidence: "fctl-v2 pkg/plugin/sdk/plugin.go defines the directional " +
			"ClientCredentialsAuthHost call set and excludes endpoint and credential material. " +
			"The operation also declares no response content schema in " +
			"openapi.yaml:15-27, so it exposes no typed result a command could " +
			"render. No legacy fctl auth command dispatches it.",
	},
}

// ExcludedIDs returns the excluded operationIds, sorted.
func ExcludedIDs() []string {
	var out []string
	for _, e := range Exclusions {
		out = append(out, e.OperationID)
	}
	sort.Strings(out)
	return out
}

// IsExcluded reports whether the operation is excluded from the command facet.
func IsExcluded(operationID string) bool {
	for _, e := range Exclusions {
		if e.OperationID == operationID {
			return true
		}
	}
	return false
}
