package test_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/formancehq/auth/cmd"
	"github.com/formancehq/auth/pkg/api"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/pkg/oidc"
	"go.uber.org/fx/fxtest"
)

func TestAuthServer(t *testing.T) {
	block, _ := pem.Decode([]byte(cmd.DefaultSigningKey))
	require.NotNil(t, block)

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	serverApp := fxtest.New(t,
		cmd.AuthServerModule(context.Background(), serverBaseURL, ":8888",
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

	t.Run("request without authorization header", func(t *testing.T) {
		requestServer(t, http.MethodGet, api.PathClients, http.StatusOK)
	})

	t.Run("request with bad token", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serverBaseURL+api.PathClients, nil)
		req.Header.Set("Authorization", oidc.PrefixBearer+"invalid")
		require.NoError(t, err)
		_, err = httpClient.Do(req)
		require.NoError(t, err)
	})

	by, _ := os.ReadFile("auth.log")
	fmt.Printf("LOGS FILE:\n%s", string(by))
	_ = os.Remove("auth.log")

	t.Run("stop", func(t *testing.T) {
		serverApp.RequireStop()
	})
}
