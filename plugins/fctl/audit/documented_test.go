package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The hand-written inventory quotes counts, revisions, and identifiers in
// prose. These tests bind those quotes to the derived report so the document
// cannot drift away from the source it describes. A count that changes in
// openapi.yaml must be edited here too, deliberately.

func readDoc(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "docs", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

// flowed collapses runs of whitespace to single spaces so an expectation can
// be written as one sentence and still match prose that the document wraps
// across lines. Without it these tests would pin line breaks rather than
// content, and would fail on any reflow of the Markdown.
func flowed(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// TestInventoryQuotesDerivedCounts proves every count the hand-written
// inventory states appears in it exactly as the report derives it.
func TestInventoryQuotesDerivedCounts(t *testing.T) {
	r := build(t)
	doc := readDoc(t, "command-inventory.md")
	t2 := r.Totals

	for _, c := range []struct {
		what string
		text string
	}{
		{"surface", fmt.Sprintf("**%d operations over %d paths**", t2.SpecOperations, t2.SpecPaths)},
		{"deprecations", fmt.Sprintf("marks **%d** deprecated", t2.DeprecatedOperations)},
		{"included", fmt.Sprintf("**%d are included**", t2.Included)},
		{"excluded", fmt.Sprintf("**%d are excluded**", t2.Excluded)},
		{"included equals baseline operations", fmt.Sprintf("The %d included operations are exactly the %d the legacy CLI reached", t2.Included, t2.BaselineOperations)},
		{"baseline shape", fmt.Sprintf("%d historical executable operations over %d historical CLI paths, %d reads and %d writes", t2.BaselineOperations, t2.BaselinePaths, t2.Reads, t2.Writes+t2.Destructive+t2.Sensitive)},
		{"duplicate mounts", fmt.Sprintf("%d paths over %d operations", t2.BaselinePaths, t2.BaselineOperations)},
		{"unmapped", fmt.Sprintf("**%d** included operations lack", t2.IncludedWithoutBaseline)},
		{"all scoped", fmt.Sprintf("All %d operations declare a security block", t2.ScopedOperations)},
		{"read scope", fmt.Sprintf("`auth:read` (**%d** operations)", t2.ReadScoped)},
		{"write scope", fmt.Sprintf("`auth:write` (**%d** operations)", t2.WriteScoped)},
		{"exact scope pin", fmt.Sprintf("`TestExactScopes` pins all %d", t2.ScopedOperations)},
		{"pagination", fmt.Sprintf("**%d** operations in the document offer pagination", t2.PaginatedOperations)},
		{"confirmations", fmt.Sprintf("All %d legacy mutation paths gated execution", t2.BaselineConfirmedPaths)},
		{"blocker count", fmt.Sprintf("**%d current admission blockers**", t2.ModuleWideBlockers)},
		{"included proven", fmt.Sprintf("Every one of the %d included operations has a proven method", t2.Included)},
	} {
		if !strings.Contains(flowed(doc), flowed(c.text)) {
			t.Errorf("command-inventory.md does not state the derived %s; expected to find %q", c.what, c.text)
		}
	}
}

func TestInventoryDoesNotPresentHistoricalPreparationBlockersAsCurrent(t *testing.T) {
	doc := flowed(readDoc(t, "command-inventory.md"))
	for _, stale := range []string{
		"client cannot be used",
		"no operation in this inventory is admission-eligible",
		"No operation is accepted into a plugin catalogue",
	} {
		if strings.Contains(doc, stale) {
			t.Errorf("command-inventory.md presents stale preparation state as current: %q", stale)
		}
	}
}

func TestGeneratedInventoryStatesNoCurrentAdmissionBlockers(t *testing.T) {
	if got := build(t).Markdown(); !strings.Contains(got, "No current admission blockers.") {
		t.Error("generated inventory does not state the empty current admission-blocker state")
	}
}

// TestInventoryPinsRevisions proves the document quotes the same full
// revisions the report pins.
func TestInventoryPinsRevisions(t *testing.T) {
	r := build(t)
	doc := readDoc(t, "command-inventory.md")
	for name, rev := range map[string]string{
		"product":  r.Revisions.Product,
		"baseline": r.Revisions.Baseline,
		"fctl-v2":  r.Revisions.FctlV2,
	} {
		if !strings.Contains(doc, rev) {
			t.Errorf("command-inventory.md does not pin the %s revision %s", name, rev)
		}
	}
}

// TestInventoryNamesEveryOperation proves no operation is silently absent from
// the hand-written document's family table.
func TestInventoryNamesEveryOperation(t *testing.T) {
	doc := readDoc(t, "command-inventory.md")
	for _, rec := range build(t).Operations {
		if !strings.Contains(doc, "`"+rec.OperationID+"`") {
			t.Errorf("command-inventory.md does not mention operation %s", rec.OperationID)
		}
	}
}

// TestInventoryNamesEveryBlockerAndDivergence proves every recorded ID is
// discussed in the document rather than only in code.
func TestInventoryNamesEveryBlockerAndDivergence(t *testing.T) {
	doc := readDoc(t, "command-inventory.md")
	for _, b := range Blockers {
		if !strings.Contains(doc, "`"+b.ID+"`") {
			t.Errorf("command-inventory.md does not discuss blocker %s", b.ID)
		}
	}
	for _, d := range Divergences {
		if !strings.Contains(doc, "`"+d.ID+"`") {
			t.Errorf("command-inventory.md does not discuss divergence %s", d.ID)
		}
	}
}

// TestInventoryRecordsTheSensitivePointer proves the display-once pointer is
// stated in the document exactly as the report derives it.
func TestInventoryRecordsTheSensitivePointer(t *testing.T) {
	doc := readDoc(t, "command-inventory.md")
	if !strings.Contains(doc, "`"+SensitivePointer+"`") {
		t.Errorf("command-inventory.md does not state the sensitive pointer %s", SensitivePointer)
	}
	if !strings.Contains(doc, "`"+SensitiveOperation+"`") {
		t.Errorf("command-inventory.md does not name the sensitive operation %s", SensitiveOperation)
	}
}

// TestInventoryClaimsNoRuntimeAcceptance is the guard that matters most: the
// preparation must not read as if a component, install, or dual-host result
// existed. Any checked acceptance box in either document fails the build.
func TestInventoryClaimsNoRuntimeAcceptance(t *testing.T) {
	for _, name := range []string{"command-inventory.md", "operations.generated.md"} {
		doc := readDoc(t, name)
		for _, forbidden := range []string{"- [x]", "* [x]", "- [X]"} {
			if strings.Contains(doc, forbidden) {
				t.Errorf("%s contains a checked acceptance box %q; this preparation claims no runtime acceptance", name, forbidden)
			}
		}
	}
}

// TestGeneratedDocumentIsCommitted proves the committed generated document
// matches a fresh render. cmd/specaudit -check enforces the same thing from
// the Justfile; this keeps `go test ./...` alone sufficient.
func TestGeneratedDocumentIsCommitted(t *testing.T) {
	want := build(t).Markdown()
	got := readDoc(t, "operations.generated.md")
	if got != want {
		t.Error("docs/operations.generated.md is out of date; run `just fctl-audit` and review the diff")
	}
}
