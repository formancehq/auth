package oidc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/formancehq/auth/pkg/oidc"
	"github.com/stretchr/testify/require"
)

func TestSigningKeyIDChangesWithKey(t *testing.T) {
	first, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	second, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	require.NotEmpty(t, oidc.SigningKeyID(first))
	require.NotEqual(t, oidc.SigningKeyID(first), oidc.SigningKeyID(second))
}
