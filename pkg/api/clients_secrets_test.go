package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/formancehq/auth/pkg"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

func syntheticClientSecret() auth.ClientSecret {
	digest := sha256.Sum256([]byte("strix-23-synthetic-secret"))
	return auth.ClientSecret{
		ID: "synthetic-secret", Hash: base64.StdEncoding.EncodeToString(digest[:]),
		LastDigits: "cret", Name: "test", Metadata: auth.Metadata{"purpose": "regression"},
	}
}

func requirePublicClientSecrets(t *testing.T, data []byte, secrets []auth.ClientSecret) {
	t.Helper()
	var client struct {
		Secrets []map[string]any `json:"secrets"`
	}
	require.NoError(t, json.Unmarshal(data, &client))
	require.Len(t, client.Secrets, len(secrets))
	for i, secret := range secrets {
		require.Equal(t, map[string]any{
			"id": secret.ID, "lastDigits": secret.LastDigits, "name": secret.Name,
			"metadata": map[string]any{"purpose": "regression"},
		}, client.Secrets[i])
		require.NotContains(t, string(data), secret.Hash)
	}
}

func TestClientSecretViewOmitsInternalFields(t *testing.T) {
	secret := syntheticClientSecret()
	for _, secrets := range [][]auth.ClientSecret{nil, {}, {secret}, {secret, secret}} {
		data, err := json.Marshal(mapBusinessClient(auth.Client{Secrets: secrets}))
		require.NoError(t, err)
		requirePublicClientSecrets(t, data, secrets)
	}
	require.True(t, secret.Check("strix-23-synthetic-secret"))
	require.False(t, secret.Check("wrong-secret"))
}

func TestClientHTTPResponsesOmitInternalSecretFields(t *testing.T) {
	withDbAndClientRouter(t, func(router chi.Router, db *bun.DB) {
		client := auth.NewClient(auth.ClientOptions{Name: "synthetic-client"})
		client.Secrets = []auth.ClientSecret{syntheticClientSecret()}
		_, err := db.NewInsert().Model(client).Exec(t.Context())
		require.NoError(t, err)

		for _, tc := range []struct {
			method string
			path   string
		}{
			{http.MethodGet, "/clients"},
			{http.MethodGet, "/clients/" + client.Id},
			{http.MethodPut, "/clients/" + client.Id},
		} {
			t.Run(tc.method+tc.path, func(t *testing.T) {
				var body io.Reader
				if tc.method == http.MethodPut {
					body = createJSONBuffer(t, client.ClientOptions)
				}
				res := httptest.NewRecorder()
				router.ServeHTTP(res, httptest.NewRequest(tc.method, tc.path, body))
				require.Equal(t, http.StatusOK, res.Code)
				if tc.path == "/clients" {
					clients := readTestResponse[[]json.RawMessage](t, res)
					require.Len(t, clients, 1)
					requirePublicClientSecrets(t, clients[0], client.Secrets)
				} else {
					requirePublicClientSecrets(t, readTestResponse[json.RawMessage](t, res), client.Secrets)
				}
			})
		}
		stored := &auth.Client{}
		require.NoError(t, db.NewSelect().Model(stored).Where("id = ?", client.Id).Scan(t.Context()))
		require.Equal(t, client.Secrets, stored.Secrets)
		require.NoError(t, stored.ValidateSecret("strix-23-synthetic-secret"))
		require.Error(t, stored.ValidateSecret("wrong-secret"))
	})
}
