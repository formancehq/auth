package core

import (
	"reflect"
	"testing"

	"github.com/formancehq/fctl-v2-poc/pkg/plugin/sdk"
)

func TestCatalogueIsTheNineOperationAuthV1Surface(t *testing.T) {
	want := map[string]struct {
		path    []string
		aliases [][]string
		op      string
		method  string
		scope   string
		risk    sdk.Risk
	}{
		"auth.v1.clients.list":           {[]string{"clients", "list"}, [][]string{{"c", "client"}, {"l", "ls"}}, "listClients", "GET", "auth:read", sdk.RiskRead},
		"auth.v1.clients.create":         {[]string{"clients", "create"}, [][]string{{"c", "client"}, {"c"}}, "createClient", "POST", "auth:write", sdk.RiskMutation},
		"auth.v1.clients.show":           {[]string{"clients", "show"}, [][]string{{"c", "client"}, {"s"}}, "readClient", "GET", "auth:read", sdk.RiskRead},
		"auth.v1.clients.update":         {[]string{"clients", "update"}, [][]string{{"c", "client"}, {"u", "upd"}}, "updateClient", "PUT", "auth:write", sdk.RiskMutation},
		"auth.v1.clients.delete":         {[]string{"clients", "delete"}, [][]string{{"c", "client"}, {"d", "del"}}, "deleteClient", "DELETE", "auth:write", sdk.RiskMutation},
		"auth.v1.clients.secrets.create": {[]string{"clients", "secrets", "create"}, [][]string{{"c", "client"}, {"sec"}, {"c"}}, "createSecret", "POST", "auth:write", sdk.RiskMutation},
		"auth.v1.clients.secrets.delete": {[]string{"clients", "secrets", "delete"}, [][]string{{"c", "client"}, {"sec"}, {"d"}}, "deleteSecret", "DELETE", "auth:write", sdk.RiskMutation},
		"auth.v1.users.list":             {[]string{"users", "list"}, [][]string{{"u", "user"}, {"l", "ls"}}, "listUsers", "GET", "auth:read", sdk.RiskRead},
		"auth.v1.users.show":             {[]string{"users", "show"}, [][]string{{"u", "user"}, {"s"}}, "readUser", "GET", "auth:read", sdk.RiskRead},
	}
	commands := Catalogue()
	if len(commands) != len(want) {
		t.Fatalf("Catalogue() length = %d, want %d", len(commands), len(want))
	}
	for _, command := range commands {
		expected, ok := want[command.ID]
		if !ok {
			t.Fatalf("unexpected command %q", command.ID)
		}
		if !reflect.DeepEqual(command.Path, expected.path) || !reflect.DeepEqual(command.PathAliases, expected.aliases) || len(command.Operations) != 1 || command.Operations[0].ID != expected.op || command.Operations[0].HTTP == nil || command.Operations[0].HTTP.Method != expected.method {
			t.Fatalf("command %q mapping = %#v", command.ID, command)
		}
		if !reflect.DeepEqual(command.Operations[0].Scopes, []string{expected.scope}) || command.Operations[0].Service != sdk.ServiceAuth || command.Risk != expected.risk {
			t.Fatalf("command %q authority = %#v", command.ID, command)
		}
		if command.ExecutionKind != sdk.ExecutionKindService || command.AuthMode != sdk.AuthModeCapability || !reflect.DeepEqual(command.Auth, []sdk.AuthRequirement{{Capability: "auth.stack"}}) || command.Target.Kind != sdk.TargetStack {
			t.Fatalf("command %q host contract = %#v", command.ID, command)
		}
		if !reflect.DeepEqual(command.Compatibility, []sdk.ServiceCompatibility{{Service: sdk.ServiceAuth, Majors: []uint32{1}}}) || command.ExecutionPolicy == nil || command.ExecutionPolicy.MaxHostRequests != 1 {
			t.Fatalf("command %q compatibility/budget = %#v", command.ID, command)
		}
	}
}

func TestCreateSecretDeclaresOneShotSensitiveMaterial(t *testing.T) {
	command, ok := commandByID("auth.v1.clients.secrets.create")
	if !ok {
		t.Fatal("create-secret command missing")
	}
	want := []sdk.SensitiveOutput{{JSONPointer: "/data/clear", AllowedDeliveries: []sdk.SensitiveDelivery{sdk.SensitiveDisplayOnce, sdk.SensitiveProfileAuth}}}
	if !reflect.DeepEqual(command.SensitiveOutputs, want) {
		t.Fatalf("SensitiveOutputs = %#v, want %#v", command.SensitiveOutputs, want)
	}
}
