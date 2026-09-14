package core

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/formancehq/fctl-v2-poc/pkg/plugin/sdk"
)

func executeRequest(command string, arguments ...string) sdk.ExecuteRequest {
	return sdk.ExecuteRequest{CommandID: command, Arguments: arguments, Target: sdk.TargetSelection{OrganizationID: "org", StackID: "stack"}, ServiceVersions: []sdk.ServiceVersion{{Service: sdk.ServiceAuth, Version: "1.0.0", Major: 1}}, Continuation: sdk.SinglePageContinuationControl()}
}

func TestExecuteDispatchesEveryAuthOperationThroughProductHTTP(t *testing.T) {
	tests := []struct {
		id, operation, method, path, body string
		args                              []string
		status                            int32
		shape                             sdk.ResultShape
	}{
		{"auth.v1.clients.list", "listClients", "GET", "/clients", `{"data":[]}`, nil, 200, sdk.ResultCollection},
		{"auth.v1.clients.create", "createClient", "POST", "/clients", `{"data":{"id":"c1","name":"app"}}`, []string{"app"}, 201, sdk.ResultObject},
		{"auth.v1.clients.show", "readClient", "GET", "/clients/c1", `{"data":{"id":"c1","name":"app"}}`, []string{"c1"}, 200, sdk.ResultObject},
		{"auth.v1.clients.update", "updateClient", "PUT", "/clients/c1", `{"data":{"id":"c1","name":"c1"}}`, []string{"c1"}, 200, sdk.ResultObject},
		{"auth.v1.clients.delete", "deleteClient", "DELETE", "/clients/c1", "", []string{"c1"}, 204, sdk.ResultObject},
		{"auth.v1.clients.secrets.create", "createSecret", "POST", "/clients/c1/secrets", `{"data":{"id":"s1","name":"main","lastDigits":"1234","clear":"must-not-emit"}}`, []string{"c1", "main"}, 200, sdk.ResultObject},
		{"auth.v1.clients.secrets.delete", "deleteSecret", "DELETE", "/clients/c1/secrets/s1", "", []string{"c1", "s1"}, 204, sdk.ResultObject},
		{"auth.v1.users.list", "listUsers", "GET", "/users", `{"data":[]}`, nil, 200, sdk.ResultCollection},
		{"auth.v1.users.show", "readUser", "GET", "/users/u1", `{"data":{"id":"u1","email":"u@example.test"}}`, []string{"u1"}, 200, sdk.ResultObject},
	}
	for _, test := range tests {
		t.Run(test.operation, func(t *testing.T) {
			host := sdk.NewMemoryHost(func(_ context.Context, request sdk.Request) (sdk.Responses, error) {
				if test.operation == "updateClient" && request.Operation == "readClient" {
					return sdk.NewResponseStream(sdk.Response{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"id":"c1","name":"c1"}}`)}), nil
				}
				if request.Service != sdk.ServiceAuth || request.Capability != "auth.stack" || request.Operation != test.operation || request.HTTP == nil || request.HTTP.Method != test.method || request.HTTP.Path != test.path {
					t.Fatalf("request = %#v", request)
				}
				return sdk.NewResponseStream(sdk.Response{Status: test.status, ContentType: contentType(test.body), Body: []byte(test.body)}), nil
			})
			if err := (Plugin{}).Execute(context.Background(), executeRequest(test.id, test.args...), host); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if len(host.Events()) != 1 || host.Events()[0].Result == nil || host.Events()[0].Result.OperationID != test.id || host.Events()[0].Result.Shape != test.shape {
				t.Fatalf("events = %#v", host.Events())
			}
			if test.status == 204 && string(host.Events()[0].Result.Data) != `{}` {
				t.Fatalf("empty mutation result = %s, want canonical JSON object", host.Events()[0].Result.Data)
			}
			if test.operation == "createSecret" {
				var result any
				if err := json.Unmarshal(host.Events()[0].Result.Data, &result); err != nil {
					t.Fatalf("decode createSecret result: %v", err)
				}
				if jsonContainsKey(result, "clear") {
					t.Fatalf("createSecret result exposes clear field: %s", host.Events()[0].Result.Data)
				}
				if jsonContainsString(result, "must-not-emit") {
					t.Fatal("createSecret result leaked the clear credential value")
				}
			}
		})
	}
}

func TestUpdatePreservesExistingValuesForOmittedFlags(t *testing.T) {
	t.Parallel()
	calls := 0
	host := sdk.NewMemoryHost(func(_ context.Context, request sdk.Request) (sdk.Responses, error) {
		calls++
		switch calls {
		case 1:
			if request.Operation != "readClient" || request.HTTP == nil || request.HTTP.Method != "GET" || request.HTTP.Path != "/clients/c1" {
				t.Fatalf("first request = %#v, want readClient", request)
			}
			return sdk.NewResponseStream(sdk.Response{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"id":"c1","name":"existing-name","public":true,"trusted":true,"description":"old description","redirectUris":["https://example.test/callback"],"postLogoutRedirectUris":["https://example.test/logout"],"metadata":{"owner":"team"},"scopes":["ledger:read"]}}`)}), nil
		case 2:
			if request.Operation != "updateClient" || request.HTTP == nil || request.HTTP.Method != "PUT" || request.HTTP.Path != "/clients/c1" {
				t.Fatalf("second request = %#v, want updateClient", request)
			}
			var body map[string]any
			if err := json.Unmarshal(request.HTTP.Body, &body); err != nil {
				t.Fatal(err)
			}
			want := map[string]any{
				"name": "existing-name", "public": true, "trusted": true,
				"description":            "new description",
				"redirectUris":           []any{"https://example.test/callback"},
				"postLogoutRedirectUris": []any{"https://example.test/logout"},
				"metadata":               map[string]any{"owner": "team"},
				"scopes":                 []any{"ledger:read"},
			}
			if !reflect.DeepEqual(body, want) {
				t.Fatalf("update body = %#v, want %#v", body, want)
			}
			return sdk.NewResponseStream(sdk.Response{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"id":"c1","name":"existing-name","description":"new description"}}`)}), nil
		default:
			t.Fatalf("unexpected request %d: %#v", calls, request)
			return sdk.NewResponseStream(), nil
		}
	})
	request := executeRequest("auth.v1.clients.update", "c1")
	request.Flags = []sdk.FlagOccurrence{{Name: "description", Value: "new description"}}
	if err := (Plugin{}).Execute(context.Background(), request, host); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("host requests = %d, want 2", calls)
	}
}

func TestUpdateAcceptsAnExplicitClientName(t *testing.T) {
	t.Parallel()
	host := sdk.NewMemoryHost(func(_ context.Context, request sdk.Request) (sdk.Responses, error) {
		switch request.Operation {
		case "readClient":
			return sdk.NewResponseStream(sdk.Response{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"id":"c1","name":"old-name"}}`)}), nil
		case "updateClient":
			var body map[string]any
			if err := json.Unmarshal(request.HTTP.Body, &body); err != nil {
				t.Fatal(err)
			}
			if body["name"] != "new-name" {
				t.Fatalf("update name = %#v, want new-name", body["name"])
			}
			return sdk.NewResponseStream(sdk.Response{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"id":"c1","name":"new-name"}}`)}), nil
		default:
			t.Fatalf("unexpected operation %q", request.Operation)
			return sdk.NewResponseStream(), nil
		}
	})
	request := executeRequest("auth.v1.clients.update", "c1")
	request.Flags = []sdk.FlagOccurrence{{Name: "name", Value: "new-name"}}
	if err := (Plugin{}).Execute(context.Background(), request, host); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRejectsAnEmptyExplicitClientName(t *testing.T) {
	t.Parallel()
	host := sdk.NewMemoryHost(func(_ context.Context, request sdk.Request) (sdk.Responses, error) {
		t.Fatalf("host request = %#v, want validation before host access", request)
		return sdk.NewResponseStream(), nil
	})
	request := executeRequest("auth.v1.clients.update", "c1")
	request.Flags = []sdk.FlagOccurrence{{Name: "name", Value: ""}}
	if err := (Plugin{}).Execute(context.Background(), request, host); err == nil {
		t.Fatal("empty explicit name accepted")
	}
}

func TestCreateSecretAcceptsTheHostSanitizedResponse(t *testing.T) {
	t.Parallel()
	host := sdk.NewMemoryHost(func(_ context.Context, request sdk.Request) (sdk.Responses, error) {
		if request.Operation != "createSecret" {
			t.Fatalf("operation = %q, want createSecret", request.Operation)
		}
		// The fctl sensitive-result boundary extracts /data/clear before the
		// generated client resumes plugin code.
		return sdk.NewResponseStream(sdk.Response{
			Status:      200,
			ContentType: "application/json",
			Body:        []byte(`{"data":{"id":"s1","name":"main","lastDigits":"1234"}}`),
		}), nil
	})

	if err := (Plugin{}).Execute(context.Background(), executeRequest("auth.v1.clients.secrets.create", "c1", "main"), host); err != nil {
		t.Fatalf("Execute(createSecret) error = %v", err)
	}
	if len(host.Events()) != 1 || host.Events()[0].Result == nil {
		t.Fatalf("events = %#v, want one result", host.Events())
	}
	if got, want := string(host.Events()[0].Result.Data), `{"name":"main","id":"s1","lastDigits":"1234"}`; got != want {
		t.Fatalf("public createSecret result = %s, want %s", got, want)
	}
}

func jsonContainsKey(value any, key string) bool {
	switch typed := value.(type) {
	case map[string]any:
		for candidate, child := range typed {
			if candidate == key || jsonContainsKey(child, key) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if jsonContainsKey(child, key) {
				return true
			}
		}
	}
	return false
}

func jsonContainsString(value any, want string) bool {
	switch typed := value.(type) {
	case string:
		return typed == want
	case map[string]any:
		for _, child := range typed {
			if jsonContainsString(child, want) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if jsonContainsString(child, want) {
				return true
			}
		}
	}
	return false
}

func TestExecuteBuildsClientMutationBodies(t *testing.T) {
	host := sdk.NewMemoryHost(func(_ context.Context, request sdk.Request) (sdk.Responses, error) {
		var body map[string]any
		if err := json.Unmarshal(request.HTTP.Body, &body); err != nil {
			t.Fatal(err)
		}
		if body["name"] != "app" || body["description"] != "desc" {
			t.Fatalf("body = %#v", body)
		}
		return sdk.NewResponseStream(sdk.Response{Status: 201, ContentType: "application/json", Body: []byte(`{"data":{"id":"c1","name":"app"}}`)}), nil
	})
	request := executeRequest("auth.v1.clients.create", "app")
	request.Flags = []sdk.FlagOccurrence{{Name: "description", Value: "desc"}, {Name: "scopes", Value: "ledger:read"}, {Name: "redirect-uri", Value: "https://example.test/callback"}}
	if err := (Plugin{}).Execute(context.Background(), request, host); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteRejectsPathDelimitersAndUnknownCommands(t *testing.T) {
	host := sdk.NewMemoryHost(func(_ context.Context, request sdk.Request) (sdk.Responses, error) {
		return sdk.NewResponseStream(sdk.Response{Status: 200, ContentType: "application/json", Body: []byte(`{"data":{"id":"client/id","name":"app"}}`)}), nil
	})
	if err := (Plugin{}).Execute(context.Background(), executeRequest("auth.v1.clients.show", "client/id"), host); err == nil {
		t.Fatal("path delimiter accepted")
	}
	if err := (Plugin{}).Execute(context.Background(), executeRequest("auth.v1.missing"), host); err == nil {
		t.Fatal("unknown command accepted")
	}
}

func contentType(body string) string {
	if body == "" {
		return ""
	}
	return "application/json"
}

func TestInputHelpersRejectAmbiguousValues(t *testing.T) {
	if _, err := parseBool("sometimes"); err == nil {
		t.Fatal("invalid bool accepted")
	}
	if value, err := parseBool(""); err != nil || value != nil {
		t.Fatalf("empty bool = %v, %v", value, err)
	}
	command, _ := commandByID("auth.v1.clients.create")
	if _, err := collectFlags(command, []sdk.FlagOccurrence{{Name: "missing", Value: "x"}}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if _, err := collectFlags(command, []sdk.FlagOccurrence{{Name: "public", Value: "true"}, {Name: "public", Value: "false"}}); err == nil {
		t.Fatal("repeated scalar accepted")
	}
}

func TestPluginMetadataDeclaresBothFacets(t *testing.T) {
	metadata := (Plugin{}).Metadata()
	if metadata.Name != Name || len(metadata.Facets) != 2 || !reflect.DeepEqual(metadata.Facets[1], sdk.Facet{Kind: sdk.FacetAuthProvider, ProtocolVersion: sdk.CurrentAuthProviderFacetProtocolVersion, Capabilities: []string{"auth.stack"}}) || !reflect.DeepEqual((Plugin{}).Commands(), Catalogue()) {
		t.Fatalf("plugin = %#v", metadata)
	}
}

func TestExecuteRejectsMissingGeneratedResult(t *testing.T) {
	host := sdk.NewMemoryHost(func(context.Context, sdk.Request) (sdk.Responses, error) {
		return sdk.NewResponseStream(sdk.Response{Status: 200, ContentType: "application/json", Body: []byte(`{}`)}), nil
	})
	if err := (Plugin{}).Execute(context.Background(), executeRequest("auth.v1.clients.show", "c1"), host); err == nil {
		t.Fatal("missing result accepted")
	}
	if err := (Plugin{}).Execute(context.Background(), sdk.ExecuteRequest{CommandID: "auth.v1.clients.list"}, host); err == nil {
		t.Fatal("invalid target accepted")
	}
	if err := emitJSON(host, "x", sdk.ResultObject, make(chan int)); err == nil {
		t.Fatal("unencodable result accepted")
	}
	var failure sdk.Failure
	if !errors.As(invalidArgument("bad"), &failure) {
		t.Fatal("invalid argument is not structured")
	}
}
