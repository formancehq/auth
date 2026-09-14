package audit

import (
	"fmt"
	"path/filepath"
	"sort"
)

// Record is one Auth operation with everything this audit can prove about it,
// plus the scoping and admission decisions recorded against it.
type Record struct {
	Operation
	Family      Family      `json:"family"`
	Risk        Risk        `json:"risk"`
	Idempotence Idempotence `json:"idempotence"`
	// Included is true when the operation is exposed by the fctl Auth command
	// facet. It is the negation of IsExcluded and is stored so the generated
	// artefacts and the golden report both pin the decision explicitly.
	Included bool `json:"included"`
	// BaselineCommands are the legacy fctl command paths that map onto this
	// operation, sorted. Empty means no legacy precedent.
	BaselineCommands []string `json:"baselineCommands"`
	// BaselineConfirmed is true when at least one mapping baseline command
	// gated execution behind approbation.
	BaselineConfirmed bool `json:"baselineConfirmed"`
	// SensitivePointer is the JSON Pointer of clear-text credential material
	// in the success response, or "" when the response carries none.
	SensitivePointer string `json:"sensitivePointer,omitempty"`
	// Blockers and Divergences are the recorded IDs, sorted.
	Blockers    []string `json:"blockers"`
	Divergences []string `json:"divergences"`
}

// Totals are the counts the inventory document quotes. Every one of them is
// derived, never transcribed.
type Totals struct {
	// SpecOperations is every operation in the document.
	SpecOperations int `json:"specOperations"`
	// UniqueOperationIDs must equal SpecOperations.
	UniqueOperationIDs int `json:"uniqueOperationIds"`
	// SpecPaths is the number of declared path items, excluding the known
	// vendor extension key.
	SpecPaths int `json:"specPaths"`
	// DeprecatedOperations is the count marked deprecated. It is 0 for the
	// current document.
	DeprecatedOperations int `json:"deprecatedOperations"`

	// Included and Excluded partition SpecOperations by command-facet scope.
	Included int `json:"included"`
	Excluded int `json:"excluded"`

	// Reads, Writes, Destructive, and Sensitive partition Included by risk.
	Reads       int `json:"reads"`
	Writes      int `json:"writes"`
	Destructive int `json:"destructive"`
	Sensitive   int `json:"sensitive"`

	// BaselinePaths is every executable legacy fctl auth leaf command.
	BaselinePaths int `json:"baselinePaths"`
	// BaselineCanonical and BaselineDuplicate partition BaselinePaths.
	BaselineCanonical int `json:"baselineCanonical"`
	BaselineDuplicate int `json:"baselineDuplicate"`
	// BaselineOperations is the number of distinct operations the baseline
	// dispatches.
	BaselineOperations int `json:"baselineOperations"`
	// BaselineConfirmedPaths is the number of baseline paths that gated on
	// approbation.
	BaselineConfirmedPaths int `json:"baselineConfirmedPaths"`

	// IncludedWithBaseline and IncludedWithoutBaseline partition Included by
	// whether the legacy CLI reached the operation.
	IncludedWithBaseline    int `json:"includedWithBaseline"`
	IncludedWithoutBaseline int `json:"includedWithoutBaseline"`

	// ScopedOperations is the number of operations declaring a security block.
	ScopedOperations int `json:"scopedOperations"`
	// ReadScoped and WriteScoped partition ScopedOperations by declared scope.
	ReadScoped  int `json:"readScoped"`
	WriteScoped int `json:"writeScoped"`

	// PaginatedOperations is the number of operations offering pagination. It
	// is 0 for the current document; see divergence `no-pagination`.
	PaginatedOperations int `json:"paginatedOperations"`

	// ModuleWideBlockers is the number of blockers applying to every
	// operation. While it is non-zero, no operation is admission-eligible.
	ModuleWideBlockers int `json:"moduleWideBlockers"`
	// BlockedOperations is the number of operations carrying any blocker.
	BlockedOperations int `json:"blockedOperations"`
	// Divergences is the number of recorded divergences.
	Divergences int `json:"divergences"`
}

// Report is the whole deterministic inventory.
type Report struct {
	// SpecDocument is the base name of the document the report was built from.
	// Only the base name is recorded so the report is identical whether it is
	// produced from the module root or from a package directory.
	SpecDocument string   `json:"specDocument"`
	Document     Document `json:"document"`
	// Revisions pins every tree this report depends on.
	Revisions Revisions `json:"revisions"`
	Totals    Totals    `json:"totals"`
	// Operations is every operation in the document, sorted by operationId.
	Operations []Record `json:"operations"`
	// DeclaredScopes is every distinct scope the operations declare, sorted.
	DeclaredScopes []string `json:"declaredScopes"`
	// Baseline is the pinned legacy command baseline, echoed so the golden
	// report fails when the baseline is edited.
	Baseline []Command `json:"baseline"`
	// Exclusions, Blockers, and Divergences are echoed for the same reason.
	Exclusions  []Exclusion  `json:"exclusions"`
	Blockers    []Blocker    `json:"blockers"`
	Divergences []Divergence `json:"divergences"`
}

// Revisions pins the trees this report depends on.
type Revisions struct {
	// Product is the Auth revision openapi.yaml was read from.
	Product string `json:"product"`
	// Baseline is the legacy fctl revision the command baseline came from.
	Baseline string `json:"baseline"`
	// FctlV2 is the fctl-v2 revision whose compatibility baseline and
	// programme plan this preparation was written against.
	FctlV2 string `json:"fctlV2"`
}

// Build reads the document at specPath and produces the full report.
func Build(specPath string) (*Report, error) {
	meta, ops, err := Load(specPath)
	if err != nil {
		return nil, err
	}

	byID := Index(ops)
	if len(byID) != len(ops) {
		return nil, fmt.Errorf("document declares %d operations but only %d unique operationIds", len(ops), len(byID))
	}

	confirmedByOp := map[string]bool{}
	for _, c := range Baseline {
		if c.Confirm {
			confirmedByOp[c.OperationID] = true
		}
	}

	report := &Report{
		SpecDocument: filepath.Base(specPath),
		Document:     meta,
		Revisions: Revisions{
			Product:  ProductRevision,
			Baseline: BaselineRevision,
			FctlV2:   FctlV2Revision,
		},
		DeclaredScopes: DeclaredScopes(ops),
		Baseline:       Baseline,
		Exclusions:     Exclusions,
		Blockers:       Blockers,
		Divergences:    Divergences,
	}

	paths := map[string]struct{}{}
	for _, op := range ops {
		family, ok := FamilyOf(op.OperationID)
		if !ok {
			return nil, fmt.Errorf("operation %s is not classified into a family", op.OperationID)
		}
		paths[op.Path] = struct{}{}

		rec := Record{
			Operation:         op,
			Family:            family,
			Risk:              RiskOf(op),
			Idempotence:       IdempotenceOf(op),
			Included:          !IsExcluded(op.OperationID),
			BaselineCommands:  CommandsFor(op.OperationID),
			BaselineConfirmed: confirmedByOp[op.OperationID],
			Blockers:          BlockersFor(op.OperationID),
			Divergences:       DivergencesFor(op.OperationID),
		}
		if op.OperationID == SensitiveOperation {
			rec.SensitivePointer = SensitivePointer
		}
		report.Operations = append(report.Operations, rec)
	}

	t := Totals{
		SpecOperations:     len(ops),
		UniqueOperationIDs: len(byID),
		SpecPaths:          len(paths),
		BaselinePaths:      len(Baseline),
		BaselineCanonical:  len(CanonicalBaseline()),
		BaselineDuplicate:  len(DuplicateBaseline()),
		BaselineOperations: len(BaselineTargets()),
		ModuleWideBlockers: len(ModuleWideBlockers()),
		Divergences:        len(Divergences),
	}
	for _, c := range Baseline {
		if c.Confirm {
			t.BaselineConfirmedPaths++
		}
	}
	for _, op := range ops {
		if op.Deprecated {
			t.DeprecatedOperations++
		}
		if op.Paginated() {
			t.PaginatedOperations++
		}
		if op.HasSecurity {
			t.ScopedOperations++
		}
		switch {
		case len(op.Scopes) == 1 && op.Scopes[0] == ScopeRead:
			t.ReadScoped++
		case len(op.Scopes) == 1 && op.Scopes[0] == ScopeWrite:
			t.WriteScoped++
		}
	}
	for _, r := range report.Operations {
		if len(r.Blockers) > 0 {
			t.BlockedOperations++
		}
		if !r.Included {
			t.Excluded++
			continue
		}
		t.Included++
		switch r.Risk {
		case RiskRead:
			t.Reads++
		case RiskWrite:
			t.Writes++
		case RiskDestructive:
			t.Destructive++
		case RiskSensitive:
			t.Sensitive++
		}
		if len(r.BaselineCommands) > 0 {
			t.IncludedWithBaseline++
		} else {
			t.IncludedWithoutBaseline++
		}
	}
	report.Totals = t

	return report, nil
}

// UnknownBaselineTargets returns baseline OperationID entries that do not
// exist in the document. A non-empty result means the pinned mapping
// references an operation the current source does not have.
func (r *Report) UnknownBaselineTargets() []string {
	present := map[string]struct{}{}
	for _, rec := range r.Operations {
		present[rec.OperationID] = struct{}{}
	}
	var missing []string
	for _, op := range BaselineTargets() {
		if _, ok := present[op]; !ok {
			missing = append(missing, op)
		}
	}
	sort.Strings(missing)
	return missing
}

// UnmappedIncluded returns included operations the baseline never reached,
// sorted. These are additions beyond legacy parity and need their own
// justification before admission.
func (r *Report) UnmappedIncluded() []string {
	var out []string
	for _, rec := range r.Operations {
		if rec.Included && len(rec.BaselineCommands) == 0 {
			out = append(out, rec.OperationID)
		}
	}
	sort.Strings(out)
	return out
}

// ByFamily groups the records by family, preserving operationId order.
func (r *Report) ByFamily() map[Family][]Record {
	out := map[Family][]Record{}
	for _, rec := range r.Operations {
		out[rec.Family] = append(out[rec.Family], rec)
	}
	return out
}

// Included returns the records the command facet exposes, in operationId
// order.
func (r *Report) Included() []Record {
	var out []Record
	for _, rec := range r.Operations {
		if rec.Included {
			out = append(out, rec)
		}
	}
	return out
}
