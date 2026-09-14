package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// specPath is the document under audit, relative to this package directory.
const specPath = "../../../openapi.yaml"

func build(t *testing.T) *Report {
	t.Helper()
	report, err := Build(specPath)
	if err != nil {
		t.Fatalf("Build(%s): %v", specPath, err)
	}
	return report
}

// TestLoadIsDeterministic proves two loads of the same document produce
// byte-identical reports. Without this the golden report proves nothing.
func TestLoadIsDeterministic(t *testing.T) {
	first, err := json.Marshal(build(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		again, err := json.Marshal(build(t))
		if err != nil {
			t.Fatal(err)
		}
		if string(first) != string(again) {
			t.Fatalf("build %d differs from build 0", i+1)
		}
	}
}

// TestGoldenReport pins the whole report. Any change to the document, the
// baseline, the exclusions, the blockers, or the divergences must be an
// explicit, reviewed diff to audit/testdata/report.json.
func TestGoldenReport(t *testing.T) {
	encoded, err := json.MarshalIndent(build(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')

	golden := filepath.Join("testdata", "report.json")
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read %s: %v (run `just fctl-audit`)", golden, err)
	}
	if string(want) != string(encoded) {
		t.Errorf("%s is out of date; run `just fctl-audit` and review the diff", golden)
	}
}

// TestSpecPathIndependence proves the report does not embed the path it was
// built from, so the artefacts are identical from the module root and from
// this package directory.
func TestSpecPathIndependence(t *testing.T) {
	direct := build(t)

	abs, err := filepath.Abs(specPath)
	if err != nil {
		t.Fatal(err)
	}
	viaAbs, err := Build(abs)
	if err != nil {
		t.Fatalf("Build(%s): %v", abs, err)
	}

	a, _ := json.Marshal(direct)
	b, _ := json.Marshal(viaAbs)
	if string(a) != string(b) {
		t.Error("report depends on how the spec path was spelled")
	}
	if direct.SpecDocument != "openapi.yaml" {
		t.Errorf("SpecDocument = %q, want openapi.yaml", direct.SpecDocument)
	}
}

// TestOperationCounts pins the operation totals the inventory quotes.
func TestOperationCounts(t *testing.T) {
	r := build(t)
	t.Run("eleven unique operations over eight paths", func(t *testing.T) {
		if r.Totals.SpecOperations != 11 {
			t.Errorf("SpecOperations = %d, want 11", r.Totals.SpecOperations)
		}
		if r.Totals.UniqueOperationIDs != r.Totals.SpecOperations {
			t.Errorf("UniqueOperationIDs = %d, want %d: the document declares a duplicate operationId",
				r.Totals.UniqueOperationIDs, r.Totals.SpecOperations)
		}
		if r.Totals.SpecPaths != 8 {
			t.Errorf("SpecPaths = %d, want 8", r.Totals.SpecPaths)
		}
	})

	t.Run("nine included, two excluded", func(t *testing.T) {
		if r.Totals.Included != 9 {
			t.Errorf("Included = %d, want 9", r.Totals.Included)
		}
		if r.Totals.Excluded != 2 {
			t.Errorf("Excluded = %d, want 2", r.Totals.Excluded)
		}
		if got := r.Totals.Included + r.Totals.Excluded; got != r.Totals.SpecOperations {
			t.Errorf("included+excluded = %d, want %d", got, r.Totals.SpecOperations)
		}
	})

	t.Run("no deprecations", func(t *testing.T) {
		if r.Totals.DeprecatedOperations != 0 {
			t.Errorf("DeprecatedOperations = %d, want 0", r.Totals.DeprecatedOperations)
		}
	})
}

// TestIncludedMatchesFctlV2Baseline is the parity assertion. The fctl-v2
// compatibility baseline records 9 Auth operations over 11 CLI paths, 4 reads
// and 5 writes. This test proves this preparation reproduces those exact
// numbers from the current document plus the pinned baseline, rather than
// restating them.
//
// The fctl-v2 table's "writes" column counts all five mutations together. This
// audit splits them further into write / destructive / sensitive, so the
// comparison is against the sum.
func TestIncludedMatchesFctlV2Baseline(t *testing.T) {
	r := build(t)
	t.Run("nine operations", func(t *testing.T) {
		if r.Totals.BaselineOperations != 9 {
			t.Errorf("BaselineOperations = %d, want 9", r.Totals.BaselineOperations)
		}
	})
	t.Run("eleven CLI paths, nine canonical and two duplicate", func(t *testing.T) {
		if r.Totals.BaselinePaths != 11 {
			t.Errorf("BaselinePaths = %d, want 11", r.Totals.BaselinePaths)
		}
		if r.Totals.BaselineCanonical != 9 {
			t.Errorf("BaselineCanonical = %d, want 9", r.Totals.BaselineCanonical)
		}
		if r.Totals.BaselineDuplicate != 2 {
			t.Errorf("BaselineDuplicate = %d, want 2", r.Totals.BaselineDuplicate)
		}
	})
	t.Run("four reads and five writes", func(t *testing.T) {
		if r.Totals.Reads != 4 {
			t.Errorf("Reads = %d, want 4", r.Totals.Reads)
		}
		mutations := r.Totals.Writes + r.Totals.Destructive + r.Totals.Sensitive
		if mutations != 5 {
			t.Errorf("writes+destructive+sensitive = %d, want 5", mutations)
		}
	})
	t.Run("every included operation has legacy precedent", func(t *testing.T) {
		if got := r.UnmappedIncluded(); len(got) != 0 {
			t.Errorf("included operations without legacy precedent: %v; each needs its own justification", got)
		}
		if r.Totals.IncludedWithBaseline != 9 {
			t.Errorf("IncludedWithBaseline = %d, want 9", r.Totals.IncludedWithBaseline)
		}
		if r.Totals.IncludedWithoutBaseline != 0 {
			t.Errorf("IncludedWithoutBaseline = %d, want 0", r.Totals.IncludedWithoutBaseline)
		}
	})
	t.Run("baseline targets exist in the document", func(t *testing.T) {
		if got := r.UnknownBaselineTargets(); len(got) != 0 {
			t.Errorf("baseline references operations the document does not declare: %v", got)
		}
	})
	t.Run("the duplicate paths are exactly the users subtree", func(t *testing.T) {
		var got []string
		for _, c := range DuplicateBaseline() {
			got = append(got, c.Path)
		}
		want := []string{"auth clients users list", "auth clients users show <user-id>"}
		if len(got) != len(want) {
			t.Fatalf("duplicate paths = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("duplicate path %d = %q, want %q", i, got[i], want[i])
			}
		}
	})
}

// TestExactScopes pins the exact per-operation scope set. RFC 0014 requires an
// exact-set check at dispatch, so a subset or superset is a failure, not an
// approximation.
func TestExactScopes(t *testing.T) {
	want := map[string][]string{
		"getOIDCWellKnowns": {ScopeRead},
		"getServerInfo":     {ScopeRead},
		"listClients":       {ScopeRead},
		"readClient":        {ScopeRead},
		"listUsers":         {ScopeRead},
		"readUser":          {ScopeRead},
		"createClient":      {ScopeWrite},
		"updateClient":      {ScopeWrite},
		"deleteClient":      {ScopeWrite},
		"createSecret":      {ScopeWrite},
		"deleteSecret":      {ScopeWrite},
	}

	r := build(t)
	if len(r.Operations) != len(want) {
		t.Fatalf("report has %d operations, the expectation covers %d", len(r.Operations), len(want))
	}

	for _, rec := range r.Operations {
		expected, ok := want[rec.OperationID]
		if !ok {
			t.Errorf("operation %s has no pinned scope expectation", rec.OperationID)
			continue
		}
		if !rec.HasSecurity {
			t.Errorf("operation %s declares no security block", rec.OperationID)
			continue
		}
		if len(rec.Scopes) != len(expected) {
			t.Errorf("operation %s scopes = %v, want exactly %v", rec.OperationID, rec.Scopes, expected)
			continue
		}
		for i := range expected {
			if rec.Scopes[i] != expected[i] {
				t.Errorf("operation %s scope %d = %q, want %q", rec.OperationID, i, rec.Scopes[i], expected[i])
			}
		}
	}

	t.Run("every operation is scoped", func(t *testing.T) {
		if r.Totals.ScopedOperations != 11 {
			t.Errorf("ScopedOperations = %d, want 11", r.Totals.ScopedOperations)
		}
	})
	t.Run("six read and five write", func(t *testing.T) {
		if r.Totals.ReadScoped != 6 {
			t.Errorf("ReadScoped = %d, want 6", r.Totals.ReadScoped)
		}
		if r.Totals.WriteScoped != 5 {
			t.Errorf("WriteScoped = %d, want 5", r.Totals.WriteScoped)
		}
	})
	t.Run("only two scopes exist", func(t *testing.T) {
		want := []string{ScopeRead, ScopeWrite}
		if len(r.DeclaredScopes) != len(want) {
			t.Fatalf("DeclaredScopes = %v, want %v", r.DeclaredScopes, want)
		}
		for i := range want {
			if r.DeclaredScopes[i] != want[i] {
				t.Errorf("DeclaredScopes[%d] = %q, want %q", i, r.DeclaredScopes[i], want[i])
			}
		}
	})
}

// TestMethodAndPath pins the wire contract of every operation.
func TestMethodAndPath(t *testing.T) {
	type wire struct{ method, path, success string }
	want := map[string]wire{
		"getOIDCWellKnowns": {"GET", "/.well-known/openid-configuration", "200"},
		"getServerInfo":     {"GET", "/_info", "200"},
		"listClients":       {"GET", "/clients", "200"},
		"createClient":      {"POST", "/clients", "201"},
		"readClient":        {"GET", "/clients/{clientId}", "200"},
		"updateClient":      {"PUT", "/clients/{clientId}", "200"},
		"deleteClient":      {"DELETE", "/clients/{clientId}", "204"},
		"createSecret":      {"POST", "/clients/{clientId}/secrets", "200"},
		"deleteSecret":      {"DELETE", "/clients/{clientId}/secrets/{secretId}", "204"},
		"listUsers":         {"GET", "/users", "200"},
		"readUser":          {"GET", "/users/{userId}", "200"},
	}

	for _, rec := range build(t).Operations {
		w, ok := want[rec.OperationID]
		if !ok {
			t.Errorf("operation %s has no pinned wire expectation", rec.OperationID)
			continue
		}
		if rec.Method != w.method {
			t.Errorf("%s method = %s, want %s", rec.OperationID, rec.Method, w.method)
		}
		if rec.Path != w.path {
			t.Errorf("%s path = %s, want %s", rec.OperationID, rec.Path, w.path)
		}
		if rec.SuccessCode != w.success {
			t.Errorf("%s success = %s, want %s", rec.OperationID, rec.SuccessCode, w.success)
		}
	}
}

// TestRiskDerivation pins the risk class of every included operation.
func TestRiskDerivation(t *testing.T) {
	want := map[string]Risk{
		"listClients":       RiskRead,
		"readClient":        RiskRead,
		"listUsers":         RiskRead,
		"readUser":          RiskRead,
		"createClient":      RiskWrite,
		"updateClient":      RiskWrite,
		"deleteClient":      RiskDestructive,
		"deleteSecret":      RiskDestructive,
		"createSecret":      RiskSensitive,
		"getOIDCWellKnowns": RiskRead,
		"getServerInfo":     RiskRead,
	}

	r := build(t)
	for _, rec := range r.Operations {
		if got := want[rec.OperationID]; rec.Risk != got {
			t.Errorf("%s risk = %s, want %s", rec.OperationID, rec.Risk, got)
		}
	}

	t.Run("included risk partition", func(t *testing.T) {
		if r.Totals.Reads != 4 {
			t.Errorf("Reads = %d, want 4", r.Totals.Reads)
		}
		if r.Totals.Writes != 2 {
			t.Errorf("Writes = %d, want 2", r.Totals.Writes)
		}
		if r.Totals.Destructive != 2 {
			t.Errorf("Destructive = %d, want 2", r.Totals.Destructive)
		}
		if r.Totals.Sensitive != 1 {
			t.Errorf("Sensitive = %d, want 1", r.Totals.Sensitive)
		}
	})
}

// TestRiskAgreesWithLegacyConfirmation cross-checks two independently sourced
// facts: the risk class derived from the document, and the approbation gate
// read from the pinned legacy tree. Every mutation confirmed, no read
// confirmed. A disagreement means one of the two sources was misread.
func TestRiskAgreesWithLegacyConfirmation(t *testing.T) {
	for _, rec := range build(t).Included() {
		mutating := rec.Risk != RiskRead
		if mutating && !rec.BaselineConfirmed {
			t.Errorf("%s is %s but no legacy path gated on approbation", rec.OperationID, rec.Risk)
		}
		if !mutating && rec.BaselineConfirmed {
			t.Errorf("%s is a read but a legacy path gated on approbation", rec.OperationID)
		}
		if mutating != rec.Mutating() {
			t.Errorf("%s risk %s disagrees with HTTP method %s", rec.OperationID, rec.Risk, rec.Method)
		}
	}
}

// TestSensitiveResult pins the display-once contract of secret creation.
func TestSensitiveResult(t *testing.T) {
	r := build(t)

	var sensitive []Record
	for _, rec := range r.Operations {
		if rec.SensitivePointer != "" {
			sensitive = append(sensitive, rec)
		}
	}
	if len(sensitive) != 1 {
		t.Fatalf("%d operations carry a sensitive pointer, want exactly 1", len(sensitive))
	}

	rec := sensitive[0]
	if rec.OperationID != "createSecret" {
		t.Errorf("sensitive operation = %s, want createSecret", rec.OperationID)
	}
	if rec.SensitivePointer != "/data/clear" {
		t.Errorf("sensitive pointer = %q, want /data/clear", rec.SensitivePointer)
	}
	if rec.Risk != RiskSensitive {
		t.Errorf("createSecret risk = %s, want %s", rec.Risk, RiskSensitive)
	}
	if rec.SuccessBody != "CreateSecretResponse" {
		t.Errorf("createSecret response = %q, want CreateSecretResponse", rec.SuccessBody)
	}
	if !rec.BaselineConfirmed {
		t.Error("createSecret must inherit the legacy approbation gate")
	}
}

// TestNoPagination pins the recorded pagination divergence. If a future
// document adds pagination this fails, forcing the divergence to be revisited
// rather than left stale.
func TestNoPagination(t *testing.T) {
	r := build(t)
	if r.Totals.PaginatedOperations != 0 {
		t.Errorf("PaginatedOperations = %d, want 0; divergence `no-pagination` is now stale",
			r.Totals.PaginatedOperations)
	}
	for _, id := range []string{"listClients", "listUsers"} {
		rec, ok := recordByID(r, id)
		if !ok {
			t.Fatalf("operation %s not found", id)
		}
		if len(rec.Parameters) != 0 {
			t.Errorf("%s declares parameters %v, want none", id, rec.Parameters)
		}
		if !contains(rec.Divergences, "no-pagination") {
			t.Errorf("%s does not carry divergence `no-pagination`", id)
		}
	}
}

// TestIdempotence pins what the document proves about repeating an operation.
func TestIdempotence(t *testing.T) {
	want := map[string]Idempotence{
		"createClient": NotIdempotent,
		"createSecret": NotIdempotent,
		"updateClient": IdempotentByMethod,
		"deleteClient": IdempotentByMethod,
		"deleteSecret": IdempotentByMethod,
		"listClients":  IdempotentByMethod,
		"readClient":   IdempotentByMethod,
		"listUsers":    IdempotentByMethod,
		"readUser":     IdempotentByMethod,
	}
	for _, rec := range build(t).Included() {
		if got := want[rec.OperationID]; rec.Idempotence != got {
			t.Errorf("%s idempotence = %s, want %s", rec.OperationID, rec.Idempotence, got)
		}
	}
}

// TestDestructiveOperationsCarryNoResponseBody records that both deletes
// return 204 with no schema, so a host cannot report what was removed.
func TestDestructiveOperationsCarryNoResponseBody(t *testing.T) {
	for _, rec := range build(t).Included() {
		if rec.Risk != RiskDestructive {
			continue
		}
		if rec.SuccessCode != "204" {
			t.Errorf("%s success = %s, want 204", rec.OperationID, rec.SuccessCode)
		}
		if rec.HasResponseBody() {
			t.Errorf("%s declares response body %q, want none", rec.OperationID, rec.SuccessBody)
		}
	}
}

// TestRequestBodies pins which operations carry a JSON request body.
func TestRequestBodies(t *testing.T) {
	want := map[string]string{
		"createClient": "CreateClientRequest",
		"updateClient": "UpdateClientRequest",
		"createSecret": "CreateSecretRequest",
	}
	for _, rec := range build(t).Operations {
		expected := want[rec.OperationID]
		if rec.RequestBody != expected {
			t.Errorf("%s request body = %q, want %q", rec.OperationID, rec.RequestBody, expected)
		}
		if rec.HasRequestBody() != (expected != "") {
			t.Errorf("%s HasRequestBody disagrees with RequestBody %q", rec.OperationID, rec.RequestBody)
		}
	}
}

// TestExclusionsAreJustified proves both exclusions carry a reason, an owner,
// evidence, and no legacy precedent. An excluded operation the legacy CLI
// reached would be a parity regression, not an exclusion.
func TestExclusionsAreJustified(t *testing.T) {
	r := build(t)

	if got := ExcludedIDs(); len(got) != 2 ||
		got[0] != "getOIDCWellKnowns" || got[1] != "getServerInfo" {
		t.Errorf("ExcludedIDs = %v, want [getOIDCWellKnowns getServerInfo]", got)
	}

	for _, e := range Exclusions {
		if e.Reason == "" || e.Owner == "" || e.Evidence == "" {
			t.Errorf("exclusion %s is missing reason, owner, or evidence", e.OperationID)
		}
		if _, ok := recordByID(r, e.OperationID); !ok {
			t.Errorf("exclusion %s names an operation the document does not declare", e.OperationID)
		}
	}

	for _, rec := range r.Operations {
		if rec.Included {
			continue
		}
		if len(rec.BaselineCommands) != 0 {
			t.Errorf("excluded operation %s was reached by legacy paths %v: that is a parity regression, not an exclusion",
				rec.OperationID, rec.BaselineCommands)
		}
		if rec.Family != FamilyDiscovery {
			t.Errorf("excluded operation %s is in family %s, want %s", rec.OperationID, rec.Family, FamilyDiscovery)
		}
	}
}

// TestEveryOperationIsClassified proves the frozen family table covers the
// document. A new operation fails here instead of vanishing.
func TestEveryOperationIsClassified(t *testing.T) {
	known := map[Family]struct{}{}
	for _, f := range Families {
		known[f] = struct{}{}
	}
	for _, rec := range build(t).Operations {
		if _, ok := FamilyOf(rec.OperationID); !ok {
			t.Errorf("operation %s is not classified", rec.OperationID)
		}
		if _, ok := known[rec.Family]; !ok {
			t.Errorf("operation %s is in unlisted family %s", rec.OperationID, rec.Family)
		}
	}
}

// TestCurrentCatalogueHasNoAdmissionBlockers proves historical preparation
// blockers cannot leak into the machine-readable state after implementation.
func TestCurrentCatalogueHasNoAdmissionBlockers(t *testing.T) {
	r := build(t)

	if r.Totals.ModuleWideBlockers != 0 {
		t.Errorf("ModuleWideBlockers = %d, want 0", r.Totals.ModuleWideBlockers)
	}
	if r.Totals.BlockedOperations != 0 {
		t.Errorf("BlockedOperations = %d, want 0", r.Totals.BlockedOperations)
	}
	for _, rec := range r.Operations {
		if rec.Blockers == nil {
			t.Errorf("%s blockers = null, want an explicit empty machine-readable list", rec.OperationID)
		}
		if len(rec.Blockers) != 0 {
			t.Errorf("%s blockers = %v, want none", rec.OperationID, rec.Blockers)
		}
	}
}

// TestBlockersAndDivergencesAreComplete proves every recorded entry carries
// the fields that make it actionable, has a unique ID, and names only
// operations the document declares.
func TestBlockersAndDivergencesAreComplete(t *testing.T) {
	r := build(t)

	seen := map[string]struct{}{}
	for _, b := range Blockers {
		if _, dup := seen[b.ID]; dup {
			t.Errorf("duplicate blocker ID %q", b.ID)
		}
		seen[b.ID] = struct{}{}
		if b.Statement == "" || b.Evidence == "" || b.Clears == "" {
			t.Errorf("blocker %s is missing statement, evidence, or clearing condition", b.ID)
		}
		for _, id := range b.OperationIDs {
			if _, ok := recordByID(r, id); !ok {
				t.Errorf("blocker %s names unknown operation %s", b.ID, id)
			}
		}
	}

	seen = map[string]struct{}{}
	for _, d := range Divergences {
		if _, dup := seen[d.ID]; dup {
			t.Errorf("duplicate divergence ID %q", d.ID)
		}
		seen[d.ID] = struct{}{}
		if d.Statement == "" || d.Evidence == "" || d.Impact == "" {
			t.Errorf("divergence %s is missing statement, evidence, or impact", d.ID)
		}
		for _, id := range d.OperationIDs {
			if _, ok := recordByID(r, id); !ok {
				t.Errorf("divergence %s names unknown operation %s", d.ID, id)
			}
		}
	}

	if r.Totals.Divergences != 7 {
		t.Errorf("Divergences = %d, want 7", r.Totals.Divergences)
	}
}

// TestDocumentMetadata pins the document's own self-description, including the
// two values that must never be mistaken for product facts.
func TestDocumentMetadata(t *testing.T) {
	r := build(t)
	if r.Document.OpenAPI != "3.0.3" {
		t.Errorf("openapi = %q, want 3.0.3", r.Document.OpenAPI)
	}
	if r.Document.Title != "Auth API" {
		t.Errorf("title = %q, want Auth API", r.Document.Title)
	}
	t.Run("info.version is not the product major", func(t *testing.T) {
		if r.Document.Version != "0.1.0" {
			t.Errorf("info.version = %q, want 0.1.0", r.Document.Version)
		}
		if blockerExists("no-live-info-major") {
			t.Error("external live-major evidence must not be represented as a current catalogue blocker")
		}
	})
	t.Run("the declared server is not the stack route", func(t *testing.T) {
		if len(r.Document.Servers) != 1 || r.Document.Servers[0] != "http://localhost:8080/" {
			t.Errorf("servers = %v, want [http://localhost:8080/]", r.Document.Servers)
		}
		if !divergenceExists("localhost-server") {
			t.Error("the declared server is a localhost address but divergence `localhost-server` is absent")
		}
	})
}

// TestRevisionsArePinned proves every revision is a full 40-character SHA-1.
// A short or placeholder revision would make the report irreproducible.
func TestRevisionsArePinned(t *testing.T) {
	r := build(t)
	for name, rev := range map[string]string{
		"product":  r.Revisions.Product,
		"baseline": r.Revisions.Baseline,
		"fctlV2":   r.Revisions.FctlV2,
	} {
		if len(rev) != 40 {
			t.Errorf("%s revision %q has length %d, want 40", name, rev, len(rev))
		}
		for _, c := range rev {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Errorf("%s revision %q is not lowercase hex", name, rev)
				break
			}
		}
	}
}

// TestVendorExtensionIsSkipped proves the loader skips the known extension key
// under `paths` and rejects any other non-path key.
func TestVendorExtensionIsSkipped(t *testing.T) {
	r := build(t)
	for _, rec := range r.Operations {
		if rec.Path == "x-speakeasy-errors" {
			t.Error("the vendor extension was loaded as a path item")
		}
	}
	if _, ok := knownPathExtensions["x-speakeasy-errors"]; !ok {
		t.Error("x-speakeasy-errors is no longer a known extension key")
	}

	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	const doc = `openapi: 3.0.3
info: {title: T, version: v}
paths:
  x-unexpected-extension: {}
`
	if err := os.WriteFile(bad, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(bad); err == nil {
		t.Error("Load accepted an unknown non-path key under paths")
	}
}

// TestLoadRejectsMalformedDocuments proves the loader fails loudly rather than
// producing a partial inventory.
func TestLoadRejectsMalformedDocuments(t *testing.T) {
	cases := map[string]string{
		"missing operationId": `openapi: 3.0.3
paths:
  /a:
    get:
      tags: [auth.v1]
      responses: {'200': {description: ok}}
`,
		"wrong tag": `openapi: 3.0.3
paths:
  /a:
    get:
      operationId: a
      tags: [other.v1]
      responses: {'200': {description: ok}}
`,
		"no 2xx response": `openapi: 3.0.3
paths:
  /a:
    get:
      operationId: a
      tags: [auth.v1]
      responses: {'400': {description: bad}}
`,
		"two 2xx responses": `openapi: 3.0.3
paths:
  /a:
    get:
      operationId: a
      tags: [auth.v1]
      responses: {'200': {description: ok}, '201': {description: made}}
`,
		"two security requirement objects": `openapi: 3.0.3
paths:
  /a:
    get:
      operationId: a
      tags: [auth.v1]
      responses: {'200': {description: ok}}
      security:
        - Authorization: [auth:read]
        - Authorization: [auth:write]
`,
		"unknown security scheme": `openapi: 3.0.3
paths:
  /a:
    get:
      operationId: a
      tags: [auth.v1]
      responses: {'200': {description: ok}}
      security:
        - Bearer: [auth:read]
`,
		"two tags": `openapi: 3.0.3
paths:
  /a:
    get:
      operationId: a
      tags: [auth.v1, auth.v2]
      responses: {'200': {description: ok}}
`,
	}

	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "doc.yaml")
			if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, _, err := Load(path); err == nil {
				t.Errorf("Load accepted a document with %s", name)
			}
		})
	}
}

// TestLoadReportsMissingDocument proves a missing file is an error, not an
// empty inventory.
func TestLoadReportsMissingDocument(t *testing.T) {
	if _, err := Build(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("Build accepted a missing document")
	}
}

// TestOperationsAreSorted proves the report's operation order is stable.
func TestOperationsAreSorted(t *testing.T) {
	r := build(t)
	ids := make([]string, 0, len(r.Operations))
	for _, rec := range r.Operations {
		ids = append(ids, rec.OperationID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("operations are not sorted by operationId: %v", ids)
	}
}

// TestMarkdownIsDeterministic proves the generated document is stable, which
// the check mode depends on.
func TestMarkdownIsDeterministic(t *testing.T) {
	first := build(t).Markdown()
	for i := 0; i < 4; i++ {
		if again := build(t).Markdown(); again != first {
			t.Fatalf("markdown render %d differs from render 0", i+1)
		}
	}
	if first == "" {
		t.Fatal("markdown render is empty")
	}
}

func recordByID(r *Report, id string) (Record, bool) {
	for _, rec := range r.Operations {
		if rec.OperationID == id {
			return rec, true
		}
	}
	return Record{}, false
}

func blockerExists(id string) bool {
	for _, b := range Blockers {
		if b.ID == id {
			return true
		}
	}
	return false
}

func divergenceExists(id string) bool {
	for _, d := range Divergences {
		if d.ID == id {
			return true
		}
	}
	return false
}

func contains(items []string, want string) bool {
	for _, i := range items {
		if i == want {
			return true
		}
	}
	return false
}
