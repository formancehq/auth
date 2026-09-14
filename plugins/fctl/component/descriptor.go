// Package component assembles the immutable Auth portable descriptor.
package component

import (
	"github.com/formancehq/auth/plugins/fctl/authfacet"
	"github.com/formancehq/auth/plugins/fctl/core"
	pb "github.com/formancehq/fctl-v2-poc/pkg/plugin/protocol/componentbridgev1alpha1"
	"github.com/formancehq/fctl-v2-poc/pkg/plugin/sdk"
)

func Descriptor() pb.Descriptor {
	plugin := core.Plugin{}
	provider := authfacet.New()
	return pb.Descriptor{
		Metadata: plugin.Metadata(), Commands: plugin.Commands(),
		AuthProviders: []pb.AuthProvider{{
			Metadata: provider.Metadata(), ProtocolVersion: sdk.CurrentAuthProviderFacetProtocolVersion, Capabilities: provider.Provides(),
		}},
	}
}
