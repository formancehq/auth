package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/formancehq/go-libs/v5/pkg/audit"
	"github.com/stretchr/testify/require"
)

const compromisedSigningPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAth3atoCXldJgHH9EWnZQ
Mvw5O+vVNKMcvrllEGQsLxvIA5xyYPnFt2xU7k1dcN5ViBqPiigVHZNeyyHcdVcl
g26zqjEwYUqH+OPiRFeBn0SwOG+dZLpOIJdKt7OjmUG0xN9egq81dbPVPBPckuWq
B9XMWmM+dtqydBX4lekj+Q1hFn5EWXXuAs9aLIc8DzPz8B+oqwLKZ6k6kC5vpj+E
aBt8ExVywrWftkWewGWRO7fLw0Fj7hamaA1ZTYEqCN+MLDLEd6qmtC2cdgVhZM0R
G2OnTiq5lGzNFmLXGOsquc35HSQjOQqcLL+e/72K3giJ1YCqYWAIIJcc/kNKU8Ht
pwIDAQAB
-----END PUBLIC KEY-----`

func TestAuditDefaultsToDisabled(t *testing.T) {
	cmd := newServeCommand()

	config, err := audit.ConfigFromFlags(cmd.Flags())
	require.NoError(t, err)
	require.False(t, config.Enabled, "HTTP audit must stay opt-in")
	require.Empty(t, config.HandledHeaderSecret)
}

func TestSigningKeyHasNoDefault(t *testing.T) {
	cmd := newServeCommand()

	signingKey, err := cmd.Flags().GetString(SigningKeyFlag)
	require.NoError(t, err)
	require.Empty(t, signingKey)
}

func TestCompromisedSigningKeyIsRejected(t *testing.T) {
	block, _ := pem.Decode([]byte(compromisedSigningPublicKey))
	require.NotNil(t, block)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	require.EqualError(t, rejectCompromisedSigningKey(key), "signing key is compromised and must be rotated")
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
