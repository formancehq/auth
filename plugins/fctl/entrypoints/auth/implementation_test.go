//go:build fctl_component_guest

package export_formance_fctl_plugin_lifecycle

import (
	"testing"

	pb "github.com/formancehq/fctl-v2-poc/pkg/plugin/protocol/componentbridgev1alpha1"
)

func TestDescribeExportsAuthCommandsAndProvider(t *testing.T) {
	descriptor, err := pb.DecodeDescriptorEnvelope(Describe())
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.Metadata.Name != "auth" || len(descriptor.Commands) != 9 || len(descriptor.AuthProviders) != 1 || descriptor.AuthProviders[0].Capabilities[0] != "auth.stack" {
		t.Fatalf("descriptor = %#v", descriptor)
	}
}
