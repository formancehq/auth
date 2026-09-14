// Package core implements the Auth-owned fctl command and auth-provider facets.
package core

import (
	"strings"

	"github.com/formancehq/fctl-v2-poc/pkg/plugin/sdk"
)

const (
	Name                 = "auth"
	Version              = "0.1.0"
	productMajor  uint32 = 1
	requestBytes  int64  = 256 << 10
	responseBytes int64  = 512 << 10
)

type commandSpec struct {
	path                []string
	aliases             [][]string
	summary             string
	arguments           []sdk.Argument
	flags               []sdk.Flag
	operation           operationSpec
	mutating, sensitive bool
}
type operationSpec struct {
	id, method, path, scope string
	requestBody             bool
}

func Catalogue() []sdk.Command {
	values := catalogueSpecs()
	commands := make([]sdk.Command, 0, len(values))
	for _, value := range values {
		commands = append(commands, value.command())
	}
	return commands
}

func (s commandSpec) command() sdk.Command {
	args, flags := normalizedArguments(s.arguments), normalizedFlags(s.flags)
	risk := sdk.RiskRead
	if s.mutating {
		risk = sdk.RiskMutation
	}
	contentTypes := []string(nil)
	if s.operation.requestBody {
		contentTypes = []string{"application/json"}
	}
	command := sdk.Command{
		ID: "auth.v1." + strings.Join(s.path, "."), ExecutionKind: sdk.ExecutionKindService, AuthMode: sdk.AuthModeCapability,
		Path: s.path, PathAliases: s.aliases, Summary: s.summary, Long: s.summary + ". Endpoint, credentials and transport are supplied by the fctl host.", Example: strings.Join(s.path, " ") + " --help",
		Arguments: args, Flags: flags, Auth: []sdk.AuthRequirement{{Capability: "auth.stack"}}, Target: sdk.TargetRequirement{Kind: sdk.TargetStack},
		Operations:    []sdk.OperationPolicy{{ID: s.operation.id, Service: sdk.ServiceAuth, Scopes: []string{s.operation.scope}, HTTP: &sdk.HTTPOperationPolicy{Method: s.operation.method, GeneratedClient: &sdk.HTTPGeneratedClientPolicy{PathTemplate: s.operation.path, RequestContentTypes: contentTypes, RequestHeaders: []string{"Accept"}, MaxRequestBytes: requestBytes, ResponseLimits: sdk.ResponseLimits{MaxMessageBytes: responseBytes, MaxMessages: 1, MaxAggregateBytes: responseBytes}}}}},
		Compatibility: []sdk.ServiceCompatibility{{Service: sdk.ServiceAuth, Majors: []uint32{productMajor}}}, Risk: risk,
		InputSchema: buildInputSchema(args, flags), RawOutputSchema: objectSchema, PublicOutputSchema: objectSchema, OutputMediaType: "application/json", ExecutionPolicy: &sdk.CommandExecutionPolicy{MaxHostRequests: 1},
	}
	if s.operation.id == "listClients" || s.operation.id == "listUsers" {
		command.RawOutputSchema, command.PublicOutputSchema = collectionSchema, collectionSchema
	}
	if s.sensitive {
		command.SensitiveOutputs = []sdk.SensitiveOutput{{JSONPointer: "/data/clear", AllowedDeliveries: []sdk.SensitiveDelivery{sdk.SensitiveDisplayOnce, sdk.SensitiveProfileAuth}}}
	}
	return command
}

func catalogueSpecs() []commandSpec {
	arg := func(name, usage string) sdk.Argument {
		return sdk.Argument{Name: name, Usage: usage, Type: sdk.ArgumentString, Required: true}
	}
	flag := func(name, usage string) sdk.Flag { return sdk.Flag{Name: name, Usage: usage, Type: sdk.FlagString} }
	array := func(name, usage string) sdk.Flag {
		return sdk.Flag{Name: name, Usage: usage, Type: sdk.FlagStringArray}
	}
	boolean := func(name, usage string) sdk.Flag { return sdk.Flag{Name: name, Usage: usage, Type: sdk.FlagBool} }
	clientFlags := []sdk.Flag{boolean("public", "Public client"), boolean("trusted", "Trusted client"), flag("description", "Client description"), array("redirect-uri", "Redirect URI"), array("post-logout-redirect-uri", "Post-logout redirect URI"), array("scopes", "Allowed scopes")}
	return []commandSpec{
		{path: []string{"clients", "list"}, aliases: [][]string{{"c", "client"}, {"l", "ls"}}, summary: "List clients", operation: operationSpec{"listClients", "GET", "/clients", "auth:read", false}},
		{path: []string{"clients", "create"}, aliases: [][]string{{"c", "client"}, {"c"}}, summary: "Create a client", arguments: []sdk.Argument{arg("name", "Client name")}, flags: clientFlags, operation: operationSpec{"createClient", "POST", "/clients", "auth:write", true}, mutating: true},
		{path: []string{"clients", "show"}, aliases: [][]string{{"c", "client"}, {"s"}}, summary: "Show a client", arguments: []sdk.Argument{arg("client-id", "Client ID")}, operation: operationSpec{"readClient", "GET", "/clients/{clientId}", "auth:read", false}},
		{path: []string{"clients", "update"}, aliases: [][]string{{"c", "client"}, {"u", "upd"}}, summary: "Update a client", arguments: []sdk.Argument{arg("client-id", "Client ID")}, flags: clientFlags, operation: operationSpec{"updateClient", "PUT", "/clients/{clientId}", "auth:write", true}, mutating: true},
		{path: []string{"clients", "delete"}, aliases: [][]string{{"c", "client"}, {"d", "del"}}, summary: "Delete a client", arguments: []sdk.Argument{arg("client-id", "Client ID")}, operation: operationSpec{"deleteClient", "DELETE", "/clients/{clientId}", "auth:write", false}, mutating: true},
		{path: []string{"clients", "secrets", "create"}, aliases: [][]string{{"c", "client"}, {"sec"}, {"c"}}, summary: "Create a client secret", arguments: []sdk.Argument{arg("client-id", "Client ID"), arg("secret-name", "Secret name")}, operation: operationSpec{"createSecret", "POST", "/clients/{clientId}/secrets", "auth:write", true}, mutating: true, sensitive: true},
		{path: []string{"clients", "secrets", "delete"}, aliases: [][]string{{"c", "client"}, {"sec"}, {"d"}}, summary: "Delete a client secret", arguments: []sdk.Argument{arg("client-id", "Client ID"), arg("secret-id", "Secret ID")}, operation: operationSpec{"deleteSecret", "DELETE", "/clients/{clientId}/secrets/{secretId}", "auth:write", false}, mutating: true},
		{path: []string{"users", "list"}, aliases: [][]string{{"u", "user"}, {"l", "ls"}}, summary: "List users", operation: operationSpec{"listUsers", "GET", "/users", "auth:read", false}},
		{path: []string{"users", "show"}, aliases: [][]string{{"u", "user"}, {"s"}}, summary: "Show a user", arguments: []sdk.Argument{arg("user-id", "User ID")}, operation: operationSpec{"readUser", "GET", "/users/{userId}", "auth:read", false}},
	}
}

func normalizedArguments(values []sdk.Argument) []sdk.Argument {
	values = append([]sdk.Argument(nil), values...)
	for i := range values {
		values[i].Completion.Kind = sdk.CompletionNone
	}
	return values
}
func normalizedFlags(values []sdk.Flag) []sdk.Flag {
	values = append([]sdk.Flag(nil), values...)
	for i := range values {
		values[i].Completion.Kind = sdk.CompletionNone
	}
	return values
}
