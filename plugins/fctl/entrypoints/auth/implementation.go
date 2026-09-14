//go:build fctl_component_guest

package export_formance_fctl_plugin_lifecycle

import (
	"fmt"

	"github.com/formancehq/auth/plugins/fctl/authfacet"
	"github.com/formancehq/auth/plugins/fctl/component"
	"github.com/formancehq/auth/plugins/fctl/core"
	portable "github.com/formancehq/fctl-v2-poc/pkg/plugin/sdk/portable/component"
)

var lifecycle = mustLifecycle()

func Describe() []byte                        { return lifecycle.Describe() }
func Start(id string, input []byte) [][]byte  { return lifecycle.Start(id, input) }
func Resume(id string, input []byte) [][]byte { return lifecycle.Resume(id, input) }
func Cancel(id string) [][]byte               { return lifecycle.Cancel(id) }
func Close(id string)                         { lifecycle.Close(id) }
func mustLifecycle() *portable.Component {
	plugin := core.Plugin{}
	value, err := portable.New(portable.Providers{Command: plugin, Auth: authfacet.New()}, component.Descriptor())
	if err != nil {
		panic(fmt.Sprintf("configure auth portable component: %v", err))
	}
	return value
}
