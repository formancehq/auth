package cmd

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/formancehq/go-libs/v3/service"
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

func TestCryptoKeyConfiguration(t *testing.T) {
	command := newServeCommand()
	material, err := command.Flags().GetString(CryptoKeyFlag)
	require.NoError(t, err)
	require.Empty(t, material)
	for _, material := range []string{"", "test", strings.Repeat("x", 31), strings.Repeat(" ", 32), strings.Repeat(" ", 32) + "test"} {
		t.Run(fmt.Sprintf("length-%d", len(material)), func(t *testing.T) {
			command := newServeCommand()
			require.NoError(t, command.Flags().Set(CryptoKeyFlag, material))
			require.EqualError(t, runServe(command, nil), "crypto key must contain at least 32 bytes of secret material")
		})
	}
	material = "synthetic-oidc-crypto-key-for-tests-only"
	first, err := deriveCryptoKey(material)
	require.NoError(t, err)
	second, err := deriveCryptoKey(material)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256([]byte(material)), first)
	require.Equal(t, first, second, "restarts and replicas must derive the same key")
	other, err := deriveCryptoKey(material + "-rotated")
	require.NoError(t, err)
	require.NotEqual(t, first, other)
}

func TestCryptoKeyEnvironmentAndFlagPrecedence(t *testing.T) {
	t.Setenv("CRYPTO_KEY", "synthetic-env-crypto-key-for-tests-only")
	command := newServeCommand()
	service.BindEnvToCommand(command)
	material, err := command.Flags().GetString(CryptoKeyFlag)
	require.NoError(t, err)
	require.Equal(t, "synthetic-env-crypto-key-for-tests-only", material)
	require.NoError(t, command.ParseFlags([]string{"--crypto-key", "synthetic-flag-crypto-key-for-tests-only"}))
	material, err = command.Flags().GetString(CryptoKeyFlag)
	require.NoError(t, err)
	require.Equal(t, "synthetic-flag-crypto-key-for-tests-only", material)
}
