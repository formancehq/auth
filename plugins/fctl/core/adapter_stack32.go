package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	authclient "github.com/formancehq/auth/pkg/client"
	"github.com/formancehq/auth/pkg/client/models/components"
	"github.com/formancehq/auth/pkg/client/models/operations"
	"github.com/formancehq/fctl-v2-poc/pkg/plugin/sdk"
	"github.com/formancehq/fctl-v2-poc/pkg/plugin/sdk/producthttp"
)

func executeStack32(ctx context.Context, request sdk.ExecuteRequest, host sdk.Host) error {
	command, ok := commandByID(request.CommandID)
	if !ok {
		return invalidArgument("unknown command %q", request.CommandID)
	}
	if err := sdk.ValidateExecuteRequest(command, request); err != nil {
		return invalidArgument("invalid execution request: %s", err)
	}
	if err := sdk.ValidateTargetSelection(command.Target, request.Target); err != nil {
		return invalidArgument("invalid target: %s", err)
	}
	flags, err := collectFlags(command, request.Flags)
	if err != nil {
		return err
	}
	bound, err := producthttp.New(host, command.Operations[0], "auth.stack")
	if err != nil {
		return fmt.Errorf("auth: configure generated client: %w", err)
	}
	client := authclient.New(authclient.WithClient(bound), authclient.WithServerURL("https://product.invalid"))
	switch request.CommandID {
	case "auth.v1.clients.list":
		response, err := client.Auth.V1.ListClients(ctx)
		if err != nil {
			return err
		}
		if response == nil || response.ListClientsResponse == nil {
			return noResult("listClients")
		}
		data := response.ListClientsResponse.Data
		if data == nil {
			data = []components.Client{}
		}
		return emitJSON(host, request.CommandID, sdk.ResultCollection, data)
	case "auth.v1.clients.create":
		body, err := clientBody(request.Arguments[0], flags)
		if err != nil {
			return err
		}
		response, err := client.Auth.V1.CreateClient(ctx, &body)
		if err != nil {
			return err
		}
		if response == nil || response.CreateClientResponse == nil || response.CreateClientResponse.Data == nil {
			return noResult("createClient")
		}
		return emitJSON(host, request.CommandID, sdk.ResultObject, response.CreateClientResponse.Data)
	case "auth.v1.clients.show":
		response, err := client.Auth.V1.ReadClient(ctx, operations.ReadClientRequest{ClientID: request.Arguments[0]})
		if err != nil {
			return err
		}
		if response == nil || response.ReadClientResponse == nil || response.ReadClientResponse.Data == nil {
			return noResult("readClient")
		}
		return emitJSON(host, request.CommandID, sdk.ResultObject, response.ReadClientResponse.Data)
	case "auth.v1.clients.update":
		body, err := clientBody(request.Arguments[0], flags)
		if err != nil {
			return err
		}
		update := components.UpdateClientRequest(body)
		response, err := client.Auth.V1.UpdateClient(ctx, operations.UpdateClientRequest{ClientID: request.Arguments[0], UpdateClientRequest: &update})
		if err != nil {
			return err
		}
		if response == nil || response.UpdateClientResponse == nil || response.UpdateClientResponse.Data == nil {
			return noResult("updateClient")
		}
		return emitJSON(host, request.CommandID, sdk.ResultObject, response.UpdateClientResponse.Data)
	case "auth.v1.clients.delete":
		_, err := client.Auth.V1.DeleteClient(ctx, operations.DeleteClientRequest{ClientID: request.Arguments[0]})
		if err != nil {
			return err
		}
		return emitEmpty(host, request.CommandID)
	case "auth.v1.clients.secrets.create":
		response, err := client.Auth.V1.CreateSecret(ctx, operations.CreateSecretRequest{ClientID: request.Arguments[0], CreateSecretRequest: &components.CreateSecretRequest{Name: request.Arguments[1]}})
		if err != nil {
			return err
		}
		if response == nil || response.CreateSecretResponse == nil || response.CreateSecretResponse.Data == nil {
			return noResult("createSecret")
		}
		secret := response.CreateSecretResponse.Data
		public := struct {
			Name       string            `json:"name"`
			Metadata   map[string]string `json:"metadata,omitempty"`
			ID         string            `json:"id"`
			LastDigits string            `json:"lastDigits"`
		}{secret.Name, secret.Metadata, secret.ID, secret.LastDigits}
		return emitJSON(host, request.CommandID, sdk.ResultObject, public)
	case "auth.v1.clients.secrets.delete":
		_, err := client.Auth.V1.DeleteSecret(ctx, operations.DeleteSecretRequest{ClientID: request.Arguments[0], SecretID: request.Arguments[1]})
		if err != nil {
			return err
		}
		return emitEmpty(host, request.CommandID)
	case "auth.v1.users.list":
		response, err := client.Auth.V1.ListUsers(ctx)
		if err != nil {
			return err
		}
		if response == nil || response.ListUsersResponse == nil {
			return noResult("listUsers")
		}
		data := response.ListUsersResponse.Data
		if data == nil {
			data = []components.User{}
		}
		return emitJSON(host, request.CommandID, sdk.ResultCollection, data)
	case "auth.v1.users.show":
		response, err := client.Auth.V1.ReadUser(ctx, operations.ReadUserRequest{UserID: request.Arguments[0]})
		if err != nil {
			return err
		}
		if response == nil || response.ReadUserResponse == nil || response.ReadUserResponse.Data == nil {
			return noResult("readUser")
		}
		return emitJSON(host, request.CommandID, sdk.ResultObject, response.ReadUserResponse.Data)
	default:
		return invalidArgument("unknown command %q", request.CommandID)
	}
}

func commandByID(id string) (sdk.Command, bool) {
	for _, command := range Catalogue() {
		if command.ID == id {
			return command, true
		}
	}
	return sdk.Command{}, false
}
func collectFlags(command sdk.Command, occurrences []sdk.FlagOccurrence) (map[string][]string, error) {
	declared := map[string]sdk.Flag{}
	for _, flag := range command.Flags {
		declared[flag.Name] = flag
	}
	values := map[string][]string{}
	for _, occurrence := range occurrences {
		flag, ok := declared[occurrence.Name]
		if !ok {
			return nil, invalidArgument("unknown flag %q", occurrence.Name)
		}
		if flag.Type != sdk.FlagStringArray && len(values[occurrence.Name]) > 0 {
			return nil, invalidArgument("flag %q is repeated", occurrence.Name)
		}
		values[occurrence.Name] = append(values[occurrence.Name], occurrence.Value)
	}
	return values, nil
}
func clientBody(name string, flags map[string][]string) (components.CreateClientRequest, error) {
	public, err := parseBool(first(flags["public"]))
	if err != nil {
		return components.CreateClientRequest{}, err
	}
	trusted, err := parseBool(first(flags["trusted"]))
	if err != nil {
		return components.CreateClientRequest{}, err
	}
	return components.CreateClientRequest{Name: name, Public: public, Trusted: trusted, Description: optionalString(first(flags["description"])), RedirectUris: flags["redirect-uri"], PostLogoutRedirectUris: flags["post-logout-redirect-uri"], Scopes: flags["scopes"]}, nil
}
func parseBool(value string) (*bool, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return nil, invalidArgument("boolean flag must be true or false")
	}
	return &parsed, nil
}
func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
func emitJSON(host sdk.Host, id string, shape sdk.ResultShape, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return host.Emit(sdk.Event{Kind: sdk.EventResult, Result: &sdk.ResultEnvelope{OperationID: id, Shape: shape, MediaType: "application/json", Data: encoded}})
}
func emitEmpty(host sdk.Host, id string) error {
	return host.Emit(sdk.Event{Kind: sdk.EventResult, Result: &sdk.ResultEnvelope{OperationID: id, Shape: sdk.ResultEmpty, MediaType: "application/json", Data: []byte(`{}`)}})
}
func noResult(id string) error { return fmt.Errorf("auth: %s returned no result", id) }
func invalidArgument(format string, values ...any) error {
	return sdk.Failure{Code: string(sdk.FailureInvalidArgument), Message: fmt.Sprintf("auth: "+format, values...)}
}
