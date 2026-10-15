package cmd

import (
	"testing"

	authlib "github.com/formancehq/go-libs/v3/auth"
	"github.com/stretchr/testify/require"
)

func TestScopeCheckingRemainsOptional(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{name: "default"},
		{name: "explicit false", args: []string{"--auth-check-scopes=false"}},
		{name: "enabled", args: []string{"--auth-check-scopes"}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newServeCommand()
			require.NoError(t, cmd.Flags().Parse(tc.args))
			value, err := cmd.Flags().GetBool(authlib.AuthCheckScopesFlag)
			require.NoError(t, err)
			require.Equal(t, tc.want, value)
		})
	}
}
