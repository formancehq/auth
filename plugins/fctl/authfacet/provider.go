// Package authfacet implements the Auth-owned auth.stack client-credentials
// provider without exposing credential or endpoint material to plugin code.
package authfacet

import (
	"context"

	"github.com/formancehq/auth/plugins/fctl/core"
	"github.com/formancehq/fctl-v2-poc/pkg/plugin/sdk"
)

const CapabilityStack = "auth.stack"

// Provider turns one host-validated final credential slot into an opaque
// service binding. OAuth endpoints, client credentials and bearer values stay
// behind ClientCredentialsAuthHost.
type Provider struct{}

func New() *Provider { return &Provider{} }

func (*Provider) Metadata() sdk.AuthProviderMetadata {
	return sdk.AuthProviderMetadata{Name: core.Name, Version: core.Version}
}

func (*Provider) Provides() []string { return []string{CapabilityStack} }

func (*Provider) Resolve(ctx context.Context, request sdk.AuthRequest, host sdk.AuthHost) (sdk.ServiceBinding, error) {
	if request.Capability != CapabilityStack || request.CredentialSlot == nil ||
		request.CredentialSlot.Provider != core.Name || request.CredentialSlot.ProviderVersion != core.Version ||
		sdk.ValidateAuthRequest(request) != nil {
		return "", denied()
	}
	broker, ok := host.(sdk.ClientCredentialsAuthHost)
	if !ok {
		return "", denied()
	}

	slot := cloneSlot(*request.CredentialSlot)
	authorized, err := broker.AuthorizeClientCredentials(ctx, sdk.AuthorizeClientCredentialsRequest{
		Slot: slot,
		Intent: sdk.ClientCredentialsIntent{
			Service: request.Service,
			Scopes:  append([]string{}, slot.Scopes...),
		},
	})
	if err != nil {
		return "", err
	}
	if authorized.CredentialHandle == "" {
		return "", denied()
	}
	bound, err := broker.BindCredential(ctx, sdk.BindCredentialRequest{
		Slot:             cloneSlot(slot),
		CredentialHandle: authorized.CredentialHandle,
		Operations:       append([]string(nil), request.Operations...),
	})
	if err != nil {
		return "", err
	}
	if bound.Binding == "" {
		return "", denied()
	}
	return sdk.ServiceBinding(bound.Binding), nil
}

func cloneSlot(slot sdk.CredentialSlot) sdk.CredentialSlot {
	slot.Scopes = append([]string{}, slot.Scopes...)
	return slot
}

func denied() error {
	return sdk.Failure{Code: string(sdk.FailureOperationNotPermitted), Message: "authentication flow is not permitted"}
}
