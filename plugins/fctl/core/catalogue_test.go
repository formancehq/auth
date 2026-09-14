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
		wantRequests := uint32(1)
		if command.ID == "auth.v1.clients.update" {
			wantRequests = 2
		}
		if !reflect.DeepEqual(command.Path, expected.path) || !reflect.DeepEqual(command.PathAliases, expected.aliases) || len(command.Operations) != int(wantRequests) || command.Operations[0].ID != expected.op || command.Operations[0].HTTP == nil || command.Operations[0].HTTP.Method != expected.method {
			t.Fatalf("command %q mapping = %#v", command.ID, command)
		}
		if !reflect.DeepEqual(command.Operations[0].Scopes, []string{expected.scope}) || command.Operations[0].Service != sdk.ServiceAuth || command.Risk != expected.risk {
			t.Fatalf("command %q authority = %#v", command.ID, command)
		}
		if command.ExecutionKind != sdk.ExecutionKindService || command.AuthMode != sdk.AuthModeCapability || !reflect.DeepEqual(command.Auth, []sdk.AuthRequirement{{Capability: "auth.stack"}}) || command.Target.Kind != sdk.TargetStack {
			t.Fatalf("command %q host contract = %#v", command.ID, command)
		}
		if !reflect.DeepEqual(command.Compatibility, []sdk.ServiceCompatibility{{Service: sdk.ServiceAuth, Majors: []uint32{2}}}) || command.ExecutionPolicy == nil || command.ExecutionPolicy.MaxHostRequests != wantRequests {
			t.Fatalf("command %q compatibility/budget = %#v", command.ID, command)
		}
		if command.ID == "auth.v1.clients.update" {
			read := command.Operations[1]
			if read.ID != "readClient" || read.Service != sdk.ServiceAuth || !reflect.DeepEqual(read.Scopes, []string{"auth:read"}) || read.HTTP == nil || read.HTTP.Method != "GET" || read.HTTP.GeneratedClient == nil || read.HTTP.GeneratedClient.PathTemplate != "/clients/{clientId}" {
				t.Fatalf("update read-before-write policy = %#v", read)
			}
		}
	}
}

// The Stack v3.2 service-info authority binds Auth to image v2.5.0, product
// major 2, and this repository's own latest release tag is v2.5.0. A catalogue
// declaring major 1 would admit execution against a service line that no
// published Stack composition serves.
func TestCatalogueDeclaresTheStackV32AuthProductMajor(t *testing.T) {
	want := []sdk.ServiceCompatibility{{Service: sdk.ServiceAuth, Majors: []uint32{2}}}
	for _, command := range Catalogue() {
		if !reflect.DeepEqual(command.Compatibility, want) {
			t.Fatalf("command %q Compatibility = %#v, want %#v", command.ID, command.Compatibility, want)
		}
	}
}

func TestCatalogueRejectsTheSupersededAuthProductMajorOne(t *testing.T) {
	for _, command := range Catalogue() {
		for _, compatibility := range command.Compatibility {
			for _, major := range compatibility.Majors {
				if major == 1 {
					t.Fatalf("command %q still declares the superseded Auth major 1", command.ID)
				}
			}
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
