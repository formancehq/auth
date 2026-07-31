package cmd

import (
	"testing"

	"github.com/formancehq/go-libs/v5/pkg/audit"
	"github.com/stretchr/testify/require"
)

func TestAuditDefaultsToDisabled(t *testing.T) {
	cmd := newServeCommand()

	config, err := audit.ConfigFromFlags(cmd.Flags())
	require.NoError(t, err)
	require.False(t, config.Enabled, "HTTP audit must stay opt-in")
	require.Empty(t, config.HandledHeaderSecret)
}

func TestAuditCanBeEnabled(t *testing.T) {
	cmd := newServeCommand()

	require.NoError(t, cmd.Flags().Parse([]string{
		"--" + audit.AuditEnabledFlag,
		"--" + audit.AuditHandledHeaderSecretFlag, "s3cret",
	}))

	config, err := audit.ConfigFromFlags(cmd.Flags())
	require.NoError(t, err)
	require.True(t, config.Enabled)
	require.Equal(t, "s3cret", config.HandledHeaderSecret)
}
