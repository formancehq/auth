package test_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/formancehq/auth/cmd"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx/fxtest"
)

func TestAuthServer(t *testing.T) {
	block, _ := pem.Decode([]byte(cmd.DefaultSigningKey))
	require.NotNil(t, block)

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	serverApp := fxtest.New(t,
		cmd.AuthServerModule(context.Background(), serverBaseURL,
			"host=localhost user=auth password=auth dbname=auth port=5432 sslmode=disable",
			key, cmd.ClientOptions{},
			"http://localhost:5556/dex",
			"gateway",
			"ZXhhbXBsZS1hcHAtc2VjcmV0"))

	t.Run("start", func(t *testing.T) {
		serverApp.RequireStart()
	})

	t.Run("health check", func(t *testing.T) {
		requestServer(t, http.MethodGet, "/_healthcheck", http.StatusOK)
	})

	t.Run("stop", func(t *testing.T) {
		serverApp.RequireStop()
	})
}
