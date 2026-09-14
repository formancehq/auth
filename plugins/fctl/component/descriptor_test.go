package component

import (
	"testing"

	"github.com/formancehq/fctl-v2-poc/pkg/plugin/sdk"
)

func TestDescriptorContainsCommandAndAuthFacets(t *testing.T) {
	descriptor := Descriptor()
	if descriptor.Metadata.Name != "auth" || len(descriptor.Commands) != 9 {
		t.Fatalf("descriptor = %#v", descriptor)
	}
	if len(descriptor.Metadata.Facets) != 2 || len(descriptor.AuthProviders) != 1 || len(descriptor.TargetProviders) != 0 || len(descriptor.SignerProviders) != 0 {
		t.Fatalf("unexpected facets = %#v", descriptor)
	}
	provider := descriptor.AuthProviders[0]
	if provider.Metadata.Name != "auth" || provider.Metadata.Version != descriptor.Metadata.Version || provider.ProtocolVersion != sdk.CurrentAuthProviderFacetProtocolVersion || len(provider.Capabilities) != 1 || provider.Capabilities[0] != "auth.stack" {
		t.Fatalf("auth provider = %#v", provider)
	}
	if err := sdk.ValidateCatalogue(descriptor.Commands, descriptor.DocumentationResources); err != nil {
		t.Fatalf("catalogue invalid: %v", err)
	}
}
