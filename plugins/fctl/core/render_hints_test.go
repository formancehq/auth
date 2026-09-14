package core

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"unicode"

	authcomponents "github.com/formancehq/auth/pkg/client/models/components"
	"github.com/formancehq/fctl-v2-poc/pkg/plugin/sdk"
)

// clientFixture carries every property the Auth `Client` schema declares,
// including the ones deliberately kept out of the table. A column proven
// against this fixture is proven against the widest result the product can
// return, not against a convenient subset.
const clientFixture = `{"id":"c1","name":"app","public":true,"trusted":false,` +
	`"description":"an application registered on the stack",` +
	`"redirectUris":["https://example.test/callback"],` +
	`"postLogoutRedirectUris":["https://example.test/logout"],` +
	`"metadata":{"owner":"team"},"scopes":["ledger:read"],` +
	`"secrets":[` + clientSecretFixture + `]}`

// clientSecretFixture is the nested `ClientSecret` a `Client` carries. It is
// spelled separately so it can be pinned to its own generated type rather than
// riding along unchecked inside the client fixture.
const clientSecretFixture = `{"id":"s1","name":"main","lastDigits":"1234","metadata":{"owner":"team"}}`

const userFixture = `{"id":"u1","subject":"Jane Doe","email":"jane@example.test"}`

// secretFixture includes `clear`, which the product returns exactly once at
// creation. The public projection must drop it.
const secretFixture = `{"id":"s1","name":"main","lastDigits":"1234",` +
	`"metadata":{"owner":"team"},"clear":"must-not-emit"}`

// wantTableColumns is the exact, ordered, stable human table of every Auth
// command whose real result carries renderable fields. Order is part of the
// contract: a stable column order is what makes successive invocations
// diffable.
//
// Commands absent from this map must declare no table hint. See
// TestCommandsWithoutRenderableResultsDeclareNoTableHint for why.
func wantTableColumns() map[string][]sdk.TableColumn {
	clientColumns := []sdk.TableColumn{
		{Header: "ID", Field: "id"},
		{Header: "Name", Field: "name"},
		{Header: "Public", Field: "public"},
		{Header: "Trusted", Field: "trusted"},
	}
	userColumns := []sdk.TableColumn{
		{Header: "ID", Field: "id"},
		{Header: "Subject", Field: "subject"},
		{Header: "Email", Field: "email"},
	}
	return map[string][]sdk.TableColumn{
		"auth.v1.clients.list":   clientColumns,
		"auth.v1.clients.create": clientColumns,
		"auth.v1.clients.show":   clientColumns,
		"auth.v1.clients.update": clientColumns,
		"auth.v1.clients.secrets.create": {
			{Header: "ID", Field: "id"},
			{Header: "Name", Field: "name"},
			{Header: "Last Digits", Field: "lastDigits"},
		},
		"auth.v1.users.list": userColumns,
		"auth.v1.users.show": userColumns,
	}
}

// commandsWithoutRenderableResults are the two 204 deletes and nothing else:
// both emit a canonical empty object, so there is no real field to put in a
// column. Inventing one would print a header the product never fills.
var commandsWithoutRenderableResults = []string{"auth.v1.clients.delete", "auth.v1.clients.secrets.delete"}

func TestCatalogueDeclaresTheExactOrderedTableColumns(t *testing.T) {
	t.Parallel()
	want := wantTableColumns()
	seen := map[string]struct{}{}
	for _, command := range Catalogue() {
		expected, ok := want[command.ID]
		if !ok {
			continue
		}
		seen[command.ID] = struct{}{}
		if command.Render.Table == nil {
			t.Errorf("command %q declares no table hint, want columns %#v", command.ID, expected)
			continue
		}
		if !reflect.DeepEqual(command.Render.Table.Columns, expected) {
			t.Errorf("command %q table columns = %#v, want %#v", command.ID, command.Render.Table.Columns, expected)
		}
	}
	// Without this, a want entry whose command left the catalogue would be
	// skipped silently and its columns would stop being checked at all.
	for id := range want {
		if _, ok := seen[id]; !ok {
			t.Errorf("want entry %q names no catalogue command", id)
		}
	}
}

// Headers are authored Title Case, matching both sources that actually spell a
// header: the shipped fctl CLI tables (`auth clients list` prints
// `ID Name Description Public Permissions`, `auth users list` prints
// `ID Subject Email`) and the fctl SDK's own RenderHints examples
// (`{Header: "Display Name"}`, `{Header: "Name"}`, `{Header: "ID"}`).
//
// The convention is derived here rather than compared against a second
// hand-written list, so a new column cannot introduce a different casing: split
// the field at camelCase boundaries, upper-case a known initialism, and Title
// Case every other word.
//
// The fctl-v2 host's `strings.ToUpper` in renderTable is not a counter-example:
// it upper-cases keys *derived from a result that supplied no layout*, and
// never touches an authored Header.
func TestTableHeadersFollowTheDocumentedTitleCaseConvention(t *testing.T) {
	t.Parallel()
	for _, command := range Catalogue() {
		if command.Render.Table == nil {
			continue
		}
		for _, column := range command.Render.Table.Columns {
			if want := titleCaseHeader(column.Field); column.Header != want {
				t.Errorf("command %q header for field %q = %q, want the conventional %q", command.ID, column.Field, column.Header, want)
			}
		}
	}
}

func TestTitleCaseHeaderSplitsCamelCaseAndKeepsInitialismsUpper(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ field, want string }{
		{"id", "ID"},
		{"name", "Name"},
		{"public", "Public"},
		{"trusted", "Trusted"},
		{"subject", "Subject"},
		{"email", "Email"},
		{"lastDigits", "Last Digits"},
		{"redirectUris", "Redirect URIs"},
		{"spec.displayName", "Display Name"},
	} {
		if got := titleCaseHeader(test.field); got != test.want {
			t.Errorf("titleCaseHeader(%q) = %q, want %q", test.field, got, test.want)
		}
	}
}

// Every catalogue command must be classified one way or the other, and the
// classification must match the catalogue.
func TestCommandsWithoutRenderableResultsDeclareNoTableHint(t *testing.T) {
	t.Parallel()
	for _, command := range Catalogue() {
		wantHint, classified := tableHintExpectation(command.ID)
		if !classified {
			t.Errorf("command %q is classified neither as table-hinted nor as hintless: add it to wantTableColumns or to commandsWithoutRenderableResults", command.ID)
			continue
		}
		switch hasHint := command.Render.Table != nil; {
		case hasHint && !wantHint:
			t.Errorf("command %q declares table columns %#v, want none: its result carries no renderable property", command.ID, command.Render.Table.Columns)
		case !hasHint && wantHint:
			t.Errorf("command %q declares no table hint, want one", command.ID)
		}
	}
}

// tableHintExpectation reports whether a command is expected to declare a table
// hint. The second result is false for a command this file classifies neither
// way, which is a gap in the test's own coverage rather than a catalogue fact.
func tableHintExpectation(id string) (wantHint, classified bool) {
	_, hinted := wantTableColumns()[id]
	hintless := slices.Contains(commandsWithoutRenderableResults, id)
	if hinted == hintless {
		return false, false
	}
	return hinted, true
}

// Every declared Field must be backed by real evidence: it resolves in the
// command's own emitted public result — driven by a fixture pinned to the
// generated Auth types — or it is declared by the public output schema. A
// command with no declared public output schema fails closed, so erasing the
// schema cannot silently retire the contract.
func TestTableColumnFieldsAreCoherentWithTheRealPublicResult(t *testing.T) {
	t.Parallel()
	for _, command := range Catalogue() {
		if command.Render.Table == nil {
			continue
		}
		t.Run(command.ID, func(t *testing.T) {
			t.Parallel()
			for _, violation := range fieldCoherenceViolations(t, command, emittedPublicResult(t, command)) {
				t.Error(violation)
			}
		})
	}
}

// The coherence check must bite on exactly the ways a future change could break
// it, and must not be satisfiable by removing the contract it checks.
func TestFieldCoherenceFailsClosedOnAMissingOrUnbackedField(t *testing.T) {
	t.Parallel()
	column := sdk.TableColumn{Header: "Last Digits", Field: "lastDigits"}
	narrowed := []byte(`{"type":"object","properties":{"id":{"type":"string"}}}`)
	result := decodeJSON(t, `{"id":"s1","lastDigits":"1234","metadata":{"owner":"team"}}`)
	for _, test := range []struct {
		name    string
		schema  []byte
		columns []sdk.TableColumn
		result  any
		want    bool
	}{
		{"exhaustive schema and real result", objectSchema, []sdk.TableColumn{column}, result, false},
		{"nil schema", nil, []sdk.TableColumn{column}, result, true},
		{"empty schema", []byte{}, []sdk.TableColumn{column}, result, true},
		{"narrowed schema still backed by the real result", narrowed, []sdk.TableColumn{column}, result, false},
		{"field backed by the schema but absent from the result", narrowed, []sdk.TableColumn{{Header: "ID", Field: "id"}}, decodeJSON(t, `{"lastDigits":"1234"}`), false},
		{"field backed by neither", objectSchema, []sdk.TableColumn{{Header: "Clear", Field: "clear"}}, result, true},
		{"renamed field", objectSchema, []sdk.TableColumn{{Header: "Last Digits", Field: "lastDigitss"}}, result, true},
		{"field resolving to a container", objectSchema, []sdk.TableColumn{{Header: "Metadata", Field: "metadata"}}, result, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			command := sdk.Command{ID: "test", PublicOutputSchema: test.schema, Render: sdk.RenderHints{Table: &sdk.TableRenderHint{Columns: test.columns}}}
			violations := fieldCoherenceViolations(t, command, test.result)
			if got := len(violations) != 0; got != test.want {
				t.Fatalf("violations = %v, want any = %v", violations, test.want)
			}
		})
	}
}

// Field is a dotted path in the fctl SDK's own examples
// (`metadata.name`, `spec.displayName`, `status.phase`). Auth declares only
// top-level fields today, so the traversal is proven directly rather than
// through a catalogue that would not exercise it.
func TestFieldPathTraversalResolvesDottedPathsGenerically(t *testing.T) {
	t.Parallel()
	object := decodeJSON(t, clientFixture)
	collection := decodeJSON(t, `[`+userFixture+`]`)
	for _, test := range []struct {
		name  string
		value any
		path  string
		want  any
		found bool
	}{
		{"top-level scalar", object, "id", "c1", true},
		{"top-level bool", object, "public", true, true},
		{"nested object member", object, "metadata.owner", "team", true},
		{"through a nested collection", object, "secrets.lastDigits", "1234", true},
		{"collection element member", collection, "subject", "Jane Doe", true},
		{"absent top-level", object, "nope", nil, false},
		{"absent below a scalar", object, "name.nope", nil, false},
		{"absent inside a nested collection", object, "secrets.nope", nil, false},
		{"container itself", object, "metadata", map[string]any{"owner": "team"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, found := resolveFieldPath(test.value, strings.Split(test.path, "."))
			if found != test.found {
				t.Fatalf("resolveFieldPath(%q) found = %v, want %v", test.path, found, test.found)
			}
			if found && !reflect.DeepEqual(got, test.want) {
				t.Fatalf("resolveFieldPath(%q) = %#v, want %#v", test.path, got, test.want)
			}
		})
	}
}

// The public output schema is the exhaustive structured contract behind
// --output json and --output yaml. Every command keeps the canonical schema for
// its result shape, and the declared shape must agree with what the adapter
// really emits. Pinning the bytes is what stops a narrowing — or an erasure —
// from passing as "permissive".
func TestPublicOutputSchemaStaysTheExhaustiveStructuredContract(t *testing.T) {
	t.Parallel()
	for _, command := range Catalogue() {
		t.Run(command.ID, func(t *testing.T) {
			t.Parallel()
			result := emittedPublicResult(t, command)
			_, isCollection := result.([]any)
			want := objectSchema
			if isCollection {
				want = collectionSchema
			}
			if !bytes.Equal(command.PublicOutputSchema, want) {
				t.Fatalf("PublicOutputSchema = %s, want the exhaustive %s", command.PublicOutputSchema, want)
			}
			// Latent until the schemas are enriched: while they stay
			// permissive there is nothing to omit. The pin above is what
			// carries the no-regression guarantee today.
			declared, informative := schemaDeclaredProperties(t, command.PublicOutputSchema)
			if !informative {
				return
			}
			for _, property := range topLevelProperties(t, command.ID, result) {
				if !slices.Contains(declared, property) {
					t.Errorf("public output schema omits emitted property %q", property)
				}
			}
		})
	}
}

// compactDetailOmissions records, per command, the properties the human table
// deliberately drops. Single-object detail commands are included on purpose:
// `auth clients show` prints a compact scalar summary rather than every
// property, which is the trade-off this repository chose. Nothing is lost —
// every omitted property below is asserted to be still present in the emitted
// public result, which is exactly what --output json and --output yaml
// serialize.
//
// An entry may only contain a container or an unbounded free-text field. A
// scalar summary field dropped from the table would be a regression, and a
// container re-added to the table would be one too.
func compactDetailOmissions() map[string][]string {
	client := []string{"description", "metadata", "postLogoutRedirectUris", "redirectUris", "scopes", "secrets"}
	return map[string][]string{
		"auth.v1.clients.list":           client,
		"auth.v1.clients.create":         client,
		"auth.v1.clients.show":           client,
		"auth.v1.clients.update":         client,
		"auth.v1.clients.secrets.create": {"metadata"},
		"auth.v1.users.list":             {},
		"auth.v1.users.show":             {},
	}
}

func TestTablesAreACompactScalarSummaryWhileStructuredOutputStaysExhaustive(t *testing.T) {
	t.Parallel()
	want := compactDetailOmissions()
	for _, command := range Catalogue() {
		if command.Render.Table == nil {
			continue
		}
		t.Run(command.ID, func(t *testing.T) {
			t.Parallel()
			expected, ok := want[command.ID]
			if !ok {
				t.Fatalf("command %q declares a table but records no compact-detail decision", command.ID)
			}
			result := emittedPublicResult(t, command)
			selected := make([]string, 0, len(command.Render.Table.Columns))
			for _, column := range command.Render.Table.Columns {
				selected = append(selected, column.Field)
				value, found := resolveFieldPath(result, strings.Split(column.Field, "."))
				if !found {
					t.Errorf("column %q selects %q, absent from the emitted public result", column.Header, column.Field)
					continue
				}
				if !isScalar(value) {
					t.Errorf("column %q selects %q, which is a container the table must not re-add: %#v", column.Header, column.Field, value)
				}
			}
			omitted := make([]string, 0)
			for _, property := range topLevelProperties(t, command.ID, result) {
				if slices.Contains(selected, property) {
					continue
				}
				omitted = append(omitted, property)
				// The trade-off is only acceptable because the structured
				// output still carries what the table dropped.
				if _, found := resolveFieldPath(result, []string{property}); !found {
					t.Errorf("omitted property %q is absent from the emitted public result", property)
				}
			}
			if !slices.Equal(omitted, expected) {
				t.Errorf("table omits %v, want exactly the recorded compact-detail omissions %v", omitted, expected)
			}
		})
	}
}

// A table column must never carry a secret, a long free-text value, or a
// nested container the renderer would have to serialize back into JSON.
func TestTableColumnsExcludeSecretsNestedAndLongValues(t *testing.T) {
	t.Parallel()
	forbidden := map[string]string{
		"clear":                  "display-once secret material",
		"secrets":                "nested array of client secrets",
		"metadata":               "nested object",
		"redirectUris":           "nested array",
		"postLogoutRedirectUris": "nested array",
		"scopes":                 "nested array",
		"description":            "unbounded free text",
	}
	for _, command := range Catalogue() {
		if command.Render.Table == nil {
			continue
		}
		for _, column := range command.Render.Table.Columns {
			if reason, bad := forbidden[column.Field]; bad {
				t.Errorf("command %q column %q selects %q: %s", command.ID, column.Header, column.Field, reason)
			}
		}
	}
}

// The create-secret table must not weaken the display-once boundary: the
// sensitive pointer stays declared, and no column resolves to its leaf.
func TestCreateSecretTableKeepsTheDisplayOnceBoundary(t *testing.T) {
	t.Parallel()
	command, ok := commandByID("auth.v1.clients.secrets.create")
	if !ok {
		t.Fatal("create-secret command missing")
	}
	want := []sdk.SensitiveOutput{{JSONPointer: "/data/clear", AllowedDeliveries: []sdk.SensitiveDelivery{sdk.SensitiveDisplayOnce, sdk.SensitiveProfileAuth}}}
	if !reflect.DeepEqual(command.SensitiveOutputs, want) {
		t.Fatalf("SensitiveOutputs = %#v, want %#v", command.SensitiveOutputs, want)
	}
	if command.Render.Table == nil {
		t.Fatal("create-secret declares no table hint")
	}
	for _, sensitive := range command.SensitiveOutputs {
		leaf := sensitive.JSONPointer[strings.LastIndex(sensitive.JSONPointer, "/")+1:]
		for _, column := range command.Render.Table.Columns {
			if column.Field == leaf {
				t.Errorf("column %q exposes the sensitive leaf %q", column.Header, leaf)
			}
		}
	}
	if slices.Contains(topLevelProperties(t, command.ID, emittedPublicResult(t, command)), "clear") {
		t.Error("the public create-secret result still carries the clear credential")
	}
}

// The fixtures above are only trustworthy if they match the generated Auth
// client the adapter really decodes into. This pins every type they encode —
// including the nested `ClientSecret` and the `Secret` that backs the only
// evidence for the `lastDigits` column — to its JSON tags.
func TestFixturesMatchTheGeneratedAuthClientTypes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		fixture string
		value   any
	}{
		{"Client", clientFixture, authcomponents.Client{}},
		{"ClientSecret", clientSecretFixture, authcomponents.ClientSecret{}},
		{"User", userFixture, authcomponents.User{}},
		{"Secret", secretFixture, authcomponents.Secret{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			want := jsonPropertyNames(reflect.TypeOf(test.value))
			var decoded map[string]any
			if err := json.Unmarshal([]byte(test.fixture), &decoded); err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(decoded))
			for key := range decoded {
				got = append(got, key)
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s fixture properties = %v, want the generated type's %v", test.name, got, want)
			}
		})
	}
}

func jsonPropertyNames(typed reflect.Type) []string {
	names := make([]string, 0, typed.NumField())
	for index := range typed.NumField() {
		tag, _, _ := strings.Cut(typed.Field(index).Tag.Get("json"), ",")
		if tag != "" && tag != "-" {
			names = append(names, tag)
		}
	}
	sort.Strings(names)
	return names
}

// titleCaseHeader derives the conventional header for a field path: the last
// dotted segment, split at camelCase boundaries, with known initialisms
// upper-cased and every other word Title Cased.
func titleCaseHeader(field string) string {
	segment := field[strings.LastIndex(field, ".")+1:]
	initialisms := map[string]string{"id": "ID", "uri": "URI", "uris": "URIs", "url": "URL", "urls": "URLs"}
	words, current := []string(nil), strings.Builder{}
	for _, letter := range segment {
		if unicode.IsUpper(letter) && current.Len() != 0 {
			words = append(words, current.String())
			current.Reset()
		}
		current.WriteRune(unicode.ToLower(letter))
	}
	if current.Len() != 0 {
		words = append(words, current.String())
	}
	for index, word := range words {
		if initialism, ok := initialisms[word]; ok {
			words[index] = initialism
			continue
		}
		words[index] = strings.ToUpper(word[:1]) + word[1:]
	}
	return strings.Join(words, " ")
}

// fieldCoherenceViolations reports every way a command's declared columns are
// not backed by real evidence. A field is backed when the emitted public result
// resolves it to a scalar, or when the public output schema declares it. A
// command with no public output schema is a violation in itself: an absent
// contract is not a permissive one, so erasing the schema cannot make the
// check pass.
func fieldCoherenceViolations(t *testing.T, command sdk.Command, result any) []string {
	t.Helper()
	violations := []string(nil)
	if len(command.PublicOutputSchema) == 0 {
		violations = append(violations, "declares no public output schema, so no column can be checked against a declared contract")
	}
	for _, column := range command.Render.Table.Columns {
		segments := strings.Split(column.Field, ".")
		value, resolved := resolveFieldPath(result, segments)
		declared, informative := schemaDeclaresFieldPath(t, command.PublicOutputSchema, segments)
		switch {
		case resolved && !isScalar(value):
			violations = append(violations, "column "+column.Header+" field "+column.Field+" resolves to a container the table cannot render")
		case resolved:
		case informative && declared:
		default:
			violations = append(violations, "column "+column.Header+" field "+column.Field+" is backed neither by the emitted public result nor by a declared public output property")
		}
	}
	return violations
}

// resolveFieldPath walks a dotted Field path through a decoded public result.
// A collection is transparent: the path is tried against each element, so a
// column declared for a list resolves through the elements it will be rendered
// from.
func resolveFieldPath(value any, segments []string) (any, bool) {
	if len(segments) == 0 {
		return value, true
	}
	switch typed := value.(type) {
	case map[string]any:
		child, ok := typed[segments[0]]
		if !ok {
			return nil, false
		}
		return resolveFieldPath(child, segments[1:])
	case []any:
		for _, element := range typed {
			if resolved, ok := resolveFieldPath(element, segments); ok {
				return resolved, true
			}
		}
		return nil, false
	default:
		return nil, false
	}
}

func isScalar(value any) bool {
	switch value.(type) {
	case map[string]any, []any:
		return false
	default:
		return true
	}
}

// jsonSchema is the subset of JSON Schema a table hint can be checked against.
type jsonSchema struct {
	Type       string                `json:"type"`
	Properties map[string]jsonSchema `json:"properties"`
	Items      *jsonSchema           `json:"items"`
}

func (s jsonSchema) element() jsonSchema {
	if s.Items != nil {
		return *s.Items
	}
	return s
}

// declaresPath reports whether the schema declares a dotted path. The second
// result is false when the schema declares no properties at the depth reached,
// which is a real fact about the contract — silence, not denial.
func (s jsonSchema) declaresPath(segments []string) (declares, informative bool) {
	node := s.element()
	if len(node.Properties) == 0 {
		return false, false
	}
	child, ok := node.Properties[segments[0]]
	if !ok {
		return false, true
	}
	if len(segments) == 1 {
		return true, true
	}
	return child.declaresPath(segments[1:])
}

func schemaDeclaresFieldPath(t *testing.T, schema []byte, segments []string) (declares, informative bool) {
	t.Helper()
	if len(schema) == 0 {
		return false, false
	}
	return decodeSchema(t, schema).declaresPath(segments)
}

// schemaDeclaredProperties reports the top-level property names a public output
// schema declares, and whether it declares any at all.
func schemaDeclaredProperties(t *testing.T, schema []byte) ([]string, bool) {
	t.Helper()
	if len(schema) == 0 {
		return nil, false
	}
	properties := decodeSchema(t, schema).element().Properties
	if len(properties) == 0 {
		return nil, false
	}
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, true
}

func decodeSchema(t *testing.T, schema []byte) jsonSchema {
	t.Helper()
	var document jsonSchema
	if err := json.Unmarshal(schema, &document); err != nil {
		t.Fatalf("decode public output schema: %v", err)
	}
	return document
}

func decodeJSON(t *testing.T, document string) any {
	t.Helper()
	var decoded any
	if err := json.Unmarshal([]byte(document), &decoded); err != nil {
		t.Fatalf("decode %s: %v", document, err)
	}
	return decoded
}

// emittedPublicResult executes the command against the widest documented
// fixture and returns the decoded public result the adapter really emitted.
func emittedPublicResult(t *testing.T, command sdk.Command) any {
	t.Helper()
	body, status, ok := resultFixture(command.ID)
	if !ok {
		t.Fatalf("no result fixture for command %q", command.ID)
	}
	host := sdk.NewMemoryHost(func(_ context.Context, request sdk.Request) (sdk.Responses, error) {
		if request.Operation == "readClient" && command.ID == "auth.v1.clients.update" {
			return sdk.NewResponseStream(sdk.Response{Status: 200, ContentType: "application/json", Body: []byte(`{"data":` + clientFixture + `}`)}), nil
		}
		return sdk.NewResponseStream(sdk.Response{Status: status, ContentType: "application/json", Body: []byte(body)}), nil
	})
	if err := (Plugin{}).Execute(context.Background(), executeRequest(command.ID, placeholderArguments(command)...), host); err != nil {
		t.Fatalf("Execute(%s) error = %v", command.ID, err)
	}
	events := host.Events()
	if len(events) != 1 || events[0].Result == nil {
		t.Fatalf("Execute(%s) events = %#v, want one result", command.ID, events)
	}
	var decoded any
	if err := json.Unmarshal(events[0].Result.Data, &decoded); err != nil {
		t.Fatalf("decode %s result: %v", command.ID, err)
	}
	return decoded
}

// topLevelProperties is the sorted property set of a public result: the
// object's own keys, or the union of the collection elements'.
func topLevelProperties(t *testing.T, id string, result any) []string {
	t.Helper()
	properties := map[string]struct{}{}
	switch typed := result.(type) {
	case map[string]any:
		for key := range typed {
			properties[key] = struct{}{}
		}
	case []any:
		for _, element := range typed {
			object, ok := element.(map[string]any)
			if !ok {
				t.Fatalf("%s collection element is not an object: %#v", id, element)
			}
			for key := range object {
				properties[key] = struct{}{}
			}
		}
	default:
		t.Fatalf("%s result is neither object nor collection: %#v", id, result)
	}
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// resultFixture pairs each command with its widest documented success body and
// the exact status the Auth document declares for it: createClient answers 201,
// both deletes answer 204 with no body, every other operation answers 200.
func resultFixture(id string) (string, int32, bool) {
	switch id {
	case "auth.v1.clients.list":
		return `{"data":[` + clientFixture + `]}`, 200, true
	case "auth.v1.clients.create":
		return `{"data":` + clientFixture + `}`, 201, true
	case "auth.v1.clients.show", "auth.v1.clients.update":
		return `{"data":` + clientFixture + `}`, 200, true
	case "auth.v1.clients.secrets.create":
		return `{"data":` + secretFixture + `}`, 200, true
	case "auth.v1.clients.delete", "auth.v1.clients.secrets.delete":
		return "", 204, true
	case "auth.v1.users.list":
		return `{"data":[` + userFixture + `]}`, 200, true
	case "auth.v1.users.show":
		return `{"data":` + userFixture + `}`, 200, true
	default:
		return "", 0, false
	}
}
