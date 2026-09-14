package audit

import "sort"

// Family is a functional grouping of Auth operations. The table is frozen: an
// operation the document adds later fails classification loudly instead of
// landing in a catch-all bucket.
type Family string

const (
	// FamilyClients is the OAuth2 client administration surface.
	FamilyClients Family = "clients"
	// FamilySecrets is the client-secret surface. It is separated from
	// FamilyClients because it is the only family that returns a credential.
	FamilySecrets Family = "secrets"
	// FamilyUsers is the read-only identity surface.
	FamilyUsers Family = "users"
	// FamilyDiscovery is the host-owned discovery surface: OIDC metadata and
	// service info. It is excluded from the command facet; see exclusions.go.
	FamilyDiscovery Family = "discovery"
)

// Families is the declaration order used by the generated artefacts.
var Families = []Family{FamilyClients, FamilySecrets, FamilyUsers, FamilyDiscovery}

// families maps each operationId the current document declares to its family.
var families = map[string]Family{
	"listClients":  FamilyClients,
	"createClient": FamilyClients,
	"readClient":   FamilyClients,
	"updateClient": FamilyClients,
	"deleteClient": FamilyClients,

	"createSecret": FamilySecrets,
	"deleteSecret": FamilySecrets,

	"listUsers": FamilyUsers,
	"readUser":  FamilyUsers,

	"getOIDCWellKnowns": FamilyDiscovery,
	"getServerInfo":     FamilyDiscovery,
}

// FamilyOf returns the operation's family. The second result is false when the
// operation is not classified, which report.Build treats as an error.
func FamilyOf(operationID string) (Family, bool) {
	f, ok := families[operationID]
	return f, ok
}

// Risk is the handling class a host must apply to an operation's execution and
// to its result.
type Risk string

const (
	// RiskRead is a non-mutating operation.
	RiskRead Risk = "read"
	// RiskWrite is a mutating operation that neither destroys state nor
	// returns a credential.
	RiskWrite Risk = "write"
	// RiskDestructive is a mutating operation that removes state. Both Auth
	// deletes return 204 with no body, so the response carries no evidence of
	// what was removed.
	RiskDestructive Risk = "destructive"
	// RiskSensitive is a mutating operation whose success response contains a
	// credential in clear text. It is exactly createSecret.
	RiskSensitive Risk = "sensitive"
)

// SensitivePointer is the RFC 6901 JSON Pointer of the clear-text secret in
// the createSecret success response.
//
// Proven from openapi.yaml: CreateSecretResponse.properties.data is a $ref to
// Secret, and Secret's allOf member declares `clear` as a *required* property
// alongside `id` and `lastDigits`. The field is therefore always present on
// success, and `Secret`'s own description states the full value is returned
// only at creation and cannot be retrieved again.
const SensitivePointer = "/data/clear"

// SensitiveOperation is the only operation carrying SensitivePointer.
const SensitiveOperation = "createSecret"

// destructive is the set of operations that remove state.
var destructive = map[string]struct{}{
	"deleteClient": {},
	"deleteSecret": {},
}

// RiskOf derives the operation's risk class from the document.
//
// The order matters: sensitivity outranks destructiveness outranks plain
// mutation. Nothing here reads the legacy CLI's confirmation flag, so the
// derived risk and the historical confirmation behaviour stay independently
// checkable against each other.
func RiskOf(op Operation) Risk {
	if op.OperationID == SensitiveOperation {
		return RiskSensitive
	}
	if _, ok := destructive[op.OperationID]; ok {
		return RiskDestructive
	}
	if op.Mutating() {
		return RiskWrite
	}
	return RiskRead
}

// Idempotence is what the document proves about repeating an operation.
type Idempotence string

const (
	// IdempotentByMethod is a GET, PUT, or DELETE: idempotent per RFC 9110
	// method semantics.
	IdempotentByMethod Idempotence = "idempotent-by-method"
	// NotIdempotent is a POST with no idempotency mechanism declared. The Auth
	// document declares no idempotency key header or request field anywhere,
	// so a retried createClient or createSecret creates a second object.
	NotIdempotent Idempotence = "not-idempotent"
)

// IdempotenceOf derives the operation's idempotence from its method.
//
// This is method semantics only. It is not a claim that the Auth server
// implements them correctly; live-service behavior remains an external
// acceptance gate.
func IdempotenceOf(op Operation) Idempotence {
	if op.Method == "POST" || op.Method == "PATCH" {
		return NotIdempotent
	}
	return IdempotentByMethod
}

// ScopeRead and ScopeWrite are the only two scopes the document's operations
// declare.
const (
	ScopeRead  = "auth:read"
	ScopeWrite = "auth:write"
)

// DeclaredScopes returns every distinct scope declared across the operations,
// sorted. It is derived from the document so a new scope cannot appear without
// changing the golden report.
func DeclaredScopes(ops []Operation) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, op := range ops {
		for _, s := range op.Scopes {
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
