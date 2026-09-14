package core

import (
	"context"

	"github.com/formancehq/fctl-v2-poc/pkg/plugin/sdk"
)

type Plugin struct{}

var _ sdk.Plugin = Plugin{}

func (Plugin) Metadata() sdk.Metadata {
	return sdk.Metadata{Name: Name, Version: Version, Facets: []sdk.Facet{
		{Kind: sdk.FacetCommandProvider, ProtocolVersion: sdk.CurrentCommandProviderFacetProtocolVersion, RequiredHostCapabilities: []string{sdk.HostCapabilityGeneratedClientV1}},
		{Kind: sdk.FacetAuthProvider, ProtocolVersion: sdk.CurrentAuthProviderFacetProtocolVersion, Capabilities: []string{"auth.stack"}},
	}}
}
func (Plugin) Commands() []sdk.Command { return Catalogue() }
func (Plugin) Execute(ctx context.Context, request sdk.ExecuteRequest, host sdk.Host) error {
	return executeStack32(ctx, request, host)
}
