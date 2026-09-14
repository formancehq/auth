package audit

import "sort"

// BaselineRevision pins the legacy fctl tree the command baseline was read
// from: module github.com/formancehq/fctl/v3, commit
// 693c58e27865f83332e6c3199d61fed81b742f41.
//
// The same revision is the authoritative parity baseline recorded by fctl-v2
// in docs/compatibility/README.md. Its Auth section states 9 historical
// executable operations over 11 historical CLI paths, 4 reads and 5 writes.
// Every count below is derived from this table and must reproduce those
// numbers; audit_test.go asserts it.
const BaselineRevision = "693c58e27865f83332e6c3199d61fed81b742f41"

// FctlV2Revision pins the fctl-v2 tree whose compatibility baseline and
// programme plan this preparation was written against.
const FctlV2Revision = "8de8c4539ea6664351762dd8dd0e865292e3f216"

// ProductRevision pins the Auth tree the operation inventory was read from.
const ProductRevision = "e4979fe9a52de6601d60d45d6c695db25f391f7a"

// Command is one executable leaf command of the legacy fctl `auth` tree.
//
// Grouping-only nodes (`auth`, `auth clients`, `auth clients secrets`,
// `auth users`, `auth clients users`) are not listed: they dispatch nothing.
// Only executable leaves are baseline entries, because only they correspond to
// an operation the plugin must be able to perform.
type Command struct {
	// Path is the full command path as invoked.
	Path string `json:"path"`
	// Aliases are the command's own aliases, not its parents'.
	Aliases []string `json:"aliases"`
	// Args is the positional argument contract as declared by cobra.
	Args string `json:"args"`
	// Confirm records that the command gated execution behind
	// fctl.WithConfirmFlag plus fctl.CheckStackApprobation.
	Confirm bool `json:"confirm"`
	// OperationID is the Auth operation the command dispatches, or "" when the
	// command has no Auth API counterpart.
	OperationID string `json:"operationId"`
	// Source is the file and line in the pinned legacy tree that proves the
	// command's declaration.
	Source string `json:"source"`
	// Duplicate marks a path that dispatches an operation another baseline
	// path already reaches. The users subtree is mounted below both `auth` and
	// `auth clients`, so two paths are duplicates by construction.
	Duplicate bool `json:"duplicate"`
}

// Baseline is the pinned legacy fctl `auth` command baseline: 11 executable
// paths over 9 distinct operations.
//
// Confirm, Aliases, and Args are each read from the cited source line, not
// inferred from the command's risk. All five writes gate on approbation and no
// read does; that is an observation about this tree, not a rule imposed on it.
var Baseline = []Command{
	{
		Path:        "auth clients list",
		Aliases:     []string{"l", "ls"},
		Args:        "ExactArgs(0)",
		OperationID: "listClients",
		Source:      "cmd/auth/clients/list.go:42-46",
	},
	{
		Path:        "auth clients create <name>",
		Aliases:     []string{"c"},
		Args:        "ExactArgs(1)",
		Confirm:     true,
		OperationID: "createClient",
		Source:      "cmd/auth/clients/create.go:58-69,90",
	},
	{
		Path:        "auth clients show <client-id>",
		Aliases:     []string{"s"},
		Args:        "ExactArgs(1)",
		OperationID: "readClient",
		Source:      "cmd/auth/clients/show.go:36-40",
	},
	{
		Path:        "auth clients update <client-id>",
		Aliases:     []string{"u", "upd"},
		Args:        "ExactArgs(1)",
		Confirm:     true,
		OperationID: "updateClient",
		Source:      "cmd/auth/clients/update.go:65-70,97",
	},
	{
		Path:        "auth clients delete <client-id>",
		Aliases:     []string{"d", "del"},
		Args:        "ExactArgs(1)",
		Confirm:     true,
		OperationID: "deleteClient",
		Source:      "cmd/auth/clients/delete.go:34-41,60",
	},
	{
		Path:        "auth clients secrets create <client-id> <secret-name>",
		Aliases:     []string{"c"},
		Args:        "ExactArgs(2)",
		Confirm:     true,
		OperationID: "createSecret",
		Source:      "cmd/auth/clients/secrets/create.go:37-43,62",
	},
	{
		Path:        "auth clients secrets delete <client-id> <secret-id>",
		Aliases:     []string{"d"},
		Args:        "ExactArgs(2)",
		Confirm:     true,
		OperationID: "deleteSecret",
		Source:      "cmd/auth/clients/secrets/delete.go:35-39,60",
	},
	{
		Path:        "auth users list",
		Aliases:     []string{"l", "ls"},
		Args:        "ExactArgs(0)",
		OperationID: "listUsers",
		Source:      "cmd/auth/users/list.go:40-43; mounted by cmd/auth/root.go:16",
	},
	{
		Path:        "auth users show <user-id>",
		Aliases:     []string{"s"},
		Args:        "ExactArgs(1)",
		OperationID: "readUser",
		Source:      "cmd/auth/users/show.go:34-37; mounted by cmd/auth/root.go:16",
	},
	{
		Path:        "auth clients users list",
		Aliases:     []string{"l", "ls"},
		Args:        "ExactArgs(0)",
		OperationID: "listUsers",
		Source:      "cmd/auth/users/list.go:40-43; mounted by cmd/auth/clients/root.go:22",
		Duplicate:   true,
	},
	{
		Path:        "auth clients users show <user-id>",
		Aliases:     []string{"s"},
		Args:        "ExactArgs(1)",
		OperationID: "readUser",
		Source:      "cmd/auth/users/show.go:34-37; mounted by cmd/auth/clients/root.go:22",
		Duplicate:   true,
	},
}

// GroupAliases records the grouping-only nodes and their aliases. They carry no
// operation but the plugin's target help, aliasing, and completion must
// reproduce them, so they are pinned rather than left to be rediscovered.
var GroupAliases = map[string][]string{
	"auth":                 {},
	"auth clients":         {"c", "client"},
	"auth clients secrets": {"sec"},
	"auth users":           {"u", "user"},
}

// CanonicalBaseline returns the baseline paths that are not duplicate mounts,
// sorted by path. There are 9, one per distinct operation.
func CanonicalBaseline() []Command {
	var out []Command
	for _, c := range Baseline {
		if !c.Duplicate {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// DuplicateBaseline returns the duplicate-mount paths, sorted by path.
func DuplicateBaseline() []Command {
	var out []Command
	for _, c := range Baseline {
		if c.Duplicate {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// BaselineTargets returns every distinct operationId the baseline dispatches,
// sorted.
func BaselineTargets() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, c := range Baseline {
		if c.OperationID == "" {
			continue
		}
		if _, dup := seen[c.OperationID]; dup {
			continue
		}
		seen[c.OperationID] = struct{}{}
		out = append(out, c.OperationID)
	}
	sort.Strings(out)
	return out
}

// CommandsFor returns the baseline paths that dispatch the operation, sorted.
func CommandsFor(operationID string) []string {
	var out []string
	for _, c := range Baseline {
		if c.OperationID == operationID {
			out = append(out, c.Path)
		}
	}
	sort.Strings(out)
	return out
}
