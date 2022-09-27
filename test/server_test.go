package test_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/formancehq/auth/cmd"
	auth "github.com/formancehq/auth/pkg"
	"github.com/formancehq/auth/pkg/api"
	"github.com/formancehq/auth/pkg/api/accesscontrol"
	authoidc "github.com/formancehq/auth/pkg/oidc"
	"github.com/formancehq/auth/pkg/storage/sqlstorage"
	"github.com/numary/go-libs/sharedapi"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/pkg/client/rp"
	"github.com/zitadel/oidc/pkg/oidc"
	"github.com/zitadel/oidc/pkg/op"
	"go.uber.org/fx/fxtest"
)

func TestAuthServer(t *testing.T) {
	httpClient := http.DefaultClient

	// Prepare a tcp connection, listening on :0 to select a random port
	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	// Compute server url, it will be the "issuer" of our oidc provider
	serverURL := fmt.Sprintf("http://%s", l.Addr().String())
	bindAddr := serverURL[16:]
	postgresUri := "host=localhost user=auth password=auth dbname=auth port=5432 sslmode=disable"
	delegatedIssuer := "http://localhost:5556/dex"
	delegatedClientID := "gateway"
	delegatedClientSecret := "ZXhhbXBsZS1hcHAtc2VjcmV0"
	staticClientsOptions := cmd.ClientOptions{Clients: []auth.ClientOptions{{
		ID:                     "test",
		Public:                 true,
		RedirectUris:           []string{"http://localhost:3000/auth-callback"},
		Name:                   "test",
		PostLogoutRedirectUris: []string{"http://localhost:3000/"},
		Trusted:                true,
	}},
	}

	block, _ := pem.Decode([]byte(cmd.DefaultSigningKey))
	require.NotNil(t, block)

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	u, err := url.Parse(serverURL)
	require.NoError(t, err)

	serverApp := fxtest.New(t,
		cmd.AuthServerModule(context.Background(), u, bindAddr, postgresUri,
			key, staticClientsOptions,
			delegatedIssuer, delegatedClientID, delegatedClientSecret))

	t.Run(fmt.Sprintf("start (%s)", bindAddr), func(t *testing.T) {
		serverApp.RequireStart()
	})

	t.Run("health check", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serverURL+"/_healthcheck", nil)
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("request without authorization header", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serverURL+"/clients", nil)
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, accesscontrol.ErrMissingAuthHeader+"\n", string(b))
	})

	t.Run("request with malformed token", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serverURL+"/clients", nil)
		req.Header.Set("Authorization", "malformed")
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, accesscontrol.ErrMalformedAuthHeader+"\n", string(b))
	})

	routes := []string{"/clients", "/scopes", "/users"}

	for _, route := range routes {
		t.Run("ERROR UNAUTHORIZED GET "+route, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serverURL+route, nil)
			req.Header.Set("Authorization", oidc.PrefixBearer+"invalid")
			require.NoError(t, err)
			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			b, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, accesscontrol.ErrVerifyAuthToken+"\n", string(b))
		})
	}

	db, err := sqlstorage.LoadGorm(sqlstorage.OpenPostgresDatabase(postgresUri))
	require.NoError(t, err)
	storage := sqlstorage.New(db)

	serverRelyingParty, err := rp.NewRelyingPartyOIDC(delegatedIssuer, delegatedClientID, delegatedClientSecret,
		fmt.Sprintf("%s/authorize/callback", serverURL), []string{"openid", "email"})
	require.NoError(t, err)

	var staticClients []auth.Client
	for _, c := range staticClientsOptions.Clients {
		staticClients = append(staticClients, *auth.NewClient(c))
	}
	storageFacade := authoidc.NewStorageFacade(storage, serverRelyingParty, key, staticClients...)
	provider, err := authoidc.NewOpenIDProvider(context.TODO(), storageFacade, serverURL)
	require.NoError(t, err)

	ar := &oidc.AuthRequest{
		ClientID: staticClientsOptions.Clients[0].ID,
	}
	authReq, err := provider.Storage().CreateAuthRequest(context.Background(), ar, "")
	require.NoError(t, err)

	client, err := provider.Storage().GetClientByClientID(context.Background(), authReq.GetClientID())
	require.NoError(t, err)

	tokenResponse, err := op.CreateTokenResponse(context.Background(), authReq, client, provider, true, "", "")
	require.NoError(t, err)

	for _, route := range routes {
		t.Run("AUTHORIZED GET "+route, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serverURL+route, nil)
			req.Header.Set("Authorization", oidc.PrefixBearer+tokenResponse.IDToken)
			require.NoError(t, err)
			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}

	t.Run("POST /clients", func(t *testing.T) {
		c := auth.ClientOptions{}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, serverURL+"/clients", buffer(t, c))
		req.Header.Set("Authorization", oidc.PrefixBearer+tokenResponse.IDToken)
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
	})

	t.Run("GET /clients", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serverURL+"/clients", nil)
		req.Header.Set("Authorization", oidc.PrefixBearer+tokenResponse.IDToken)
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		by, err := httputil.DumpResponse(resp, true)
		require.NoError(t, err)
		fmt.Printf("RESP:%s\n", string(by))
		cur := decodeCursorResponse[api.ClientView](t, resp.Body)
		require.True(t, len(cur.Data) == 1)
	})

	t.Run("stop", func(t *testing.T) {
		serverApp.RequireStop()
	})
}

func buffer(t *testing.T, v any) *bytes.Buffer {
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewBuffer(data)
}

func decodeCursorResponse[T any](t *testing.T, reader io.Reader) *sharedapi.Cursor[T] {
	res := sharedapi.BaseResponse[T]{}
	err := json.NewDecoder(reader).Decode(&res)
	require.NoError(t, err)
	return res.Cursor
}
