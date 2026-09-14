package core

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

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
	`"secrets":[{"id":"s1","name":"main","lastDigits":"1234"}]}`

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

func TestCatalogueDeclaresTheExactOrderedTableColumns(t *testing.T) {
	t.Parallel()
	want := wantTableColumns()
	for _, command := range Catalogue() {
		expected, ok := want[command.ID]
		if !ok {
			continue
		}
		if command.Render.Table == nil {
			t.Errorf("command %q declares no table hint, want columns %#v", command.ID, expected)
			continue
		}
		if !reflect.DeepEqual(command.Render.Table.Columns, expected) {
			t.Errorf("command %q table columns = %#v, want %#v", command.ID, command.Render.Table.Columns, expected)
		}
	}
}

// The two 204 deletes and nothing else: both emit a canonical empty object, so
// there is no real field to put in a column. Inventing one would print a
// header the product never fills.
func TestCommandsWithoutRenderableResultsDeclareNoTableHint(t *testing.T) {
	t.Parallel()
	wantAbsent := []string{"auth.v1.clients.delete", "auth.v1.clients.secrets.delete"}
	want := wantTableColumns()
	for _, command := range Catalogue() {
		_, hasTable := want[command.ID]
		if hasTable == slices.Contains(wantAbsent, command.ID) {
			t.Fatalf("command %q is both expected to have and to lack a table hint", command.ID)
		}
		if !hasTable && command.Render.Table != nil {
			t.Errorf("command %q declares table columns %#v, want none", command.ID, command.Render.Table.Columns)
		}
	}
}

// Every declared Field must name a property the command's real public result
// actually carries. The property set is not asserted from a hand-written list
// here: it is read back from the adapter's own emitted envelope, driven by the
// widest documented fixture.
func TestTableColumnFieldsAreCoherentWithTheRealPublicResult(t *testing.T) {
	t.Parallel()
	for _, command := range Catalogue() {
		if command.Render.Table == nil {
			continue
		}
		t.Run(command.ID, func(t *testing.T) {
			t.Parallel()
			properties := emittedItemProperties(t, command)
			for _, column := range command.Render.Table.Columns {
				if !slices.Contains(properties, column.Field) {
					t.Errorf("column %q field %q is not a property of the real public result %v", column.Header, column.Field, properties)
				}
				if declared, ok := declaredSchemaProperties(t, command.PublicOutputSchema); ok && !slices.Contains(declared, column.Field) {
					t.Errorf("column %q field %q is not a declared public output property %v", column.Header, column.Field, declared)
				}
			}
		})
	}
}

// The public output schema stays the exhaustive JSON/YAML contract. Narrowing
// it to the table columns would make `--output json` lose fields that only the
// human view was allowed to drop.
func TestPublicOutputSchemaRemainsExhaustiveAlongsideTheTableHint(t *testing.T) {
	t.Parallel()
	for _, command := range Catalogue() {
		if command.Render.Table == nil {
			continue
		}
		declared, ok := declaredSchemaProperties(t, command.PublicOutputSchema)
		if !ok {
			continue
		}
		properties := emittedItemProperties(t, command)
		for _, property := range properties {
			if !slices.Contains(declared, property) {
				t.Errorf("command %q public output schema omits emitted property %q", command.ID, property)
			}
		}
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
	if slices.Contains(emittedItemProperties(t, command), "clear") {
		t.Error("the public create-secret result still carries the clear credential")
	}
}

// The fixtures above are only trustworthy if they match the generated Auth
// client the adapter really decodes into. This pins them to its JSON tags.
func TestFixturesMatchTheGeneratedAuthClientTypes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		fixture string
		value   any
	}{
		{"Client", clientFixture, authcomponents.Client{}},
		{"User", userFixture, authcomponents.User{}},
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

// emittedItemProperties executes the command against the widest documented
// fixture and returns the sorted top-level property names of the public
// result: the object's own keys, or the union of the collection elements'.
func emittedItemProperties(t *testing.T, command sdk.Command) []string {
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
	properties := map[string]struct{}{}
	switch typed := decoded.(type) {
	case map[string]any:
		for key := range typed {
			properties[key] = struct{}{}
		}
	case []any:
		for _, element := range typed {
			object, ok := element.(map[string]any)
			if !ok {
				t.Fatalf("%s collection element is not an object: %#v", command.ID, element)
			}
			for key := range object {
				properties[key] = struct{}{}
			}
		}
	default:
		t.Fatalf("%s result is neither object nor collection: %#v", command.ID, decoded)
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
// every other rendered operation answers 200.
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
	case "auth.v1.users.list":
		return `{"data":[` + userFixture + `]}`, 200, true
	case "auth.v1.users.show":
		return `{"data":` + userFixture + `}`, 200, true
	default:
		return "", 0, false
	}
}

// declaredSchemaProperties reports the top-level property names a public
// output schema declares. The second result is false for a schema that
// declares none, which is a real fact about the contract rather than an empty
// property set.
func declaredSchemaProperties(t *testing.T, schema []byte) ([]string, bool) {
	t.Helper()
	if len(schema) == 0 {
		return nil, false
	}
	var document struct {
		Type       string                     `json:"type"`
		Properties map[string]json.RawMessage `json:"properties"`
		Items      *struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"items"`
	}
	if err := json.Unmarshal(schema, &document); err != nil {
		t.Fatalf("decode public output schema: %v", err)
	}
	declared := document.Properties
	if document.Type == "array" && document.Items != nil {
		declared = document.Items.Properties
	}
	if len(declared) == 0 {
		return nil, false
	}
	names := make([]string, 0, len(declared))
	for name := range declared {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, true
}
