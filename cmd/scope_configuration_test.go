package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScopeCheckingCannotBeConfigured(t *testing.T) {
	cmd := newServeCommand()
	require.Nil(t, cmd.Flags().Lookup("auth-check-scopes"))
	require.NoError(t, cmd.Flags().Parse(nil))

	for _, arg := range []string{"--auth-check-scopes", "--auth-check-scopes=true", "--auth-check-scopes=false"} {
		t.Run(arg, func(t *testing.T) {
			require.ErrorContains(t, newServeCommand().Flags().Parse([]string{arg}), "unknown flag: --auth-check-scopes")
		})
	}
}
