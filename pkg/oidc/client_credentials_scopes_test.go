package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	auth "github.com/formancehq/auth/pkg"
	"github.com/formancehq/auth/pkg/oidc"
	"github.com/formancehq/auth/pkg/storage/sqlstorage"
	"github.com/formancehq/go-libs/v3/bun/bunconnect"
	"github.com/formancehq/go-libs/v3/logging"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v2/pkg/op"
)

func TestClientCredentialsGrantedScopes(t *testing.T) {
	for _, static := range []bool{false, true} {
		name := "database"
		if static {
			name = "static"
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name       string
				configured []string
				requested  *string
				want       []string
				invalid    bool
			}{
				{name: "omitted", configured: []string{"openid", "auth:read", "auth:write"}, want: []string{"openid", "auth:read", "auth:write"}},
				{name: "subset", configured: []string{"auth:read", "auth:write"}, requested: scopeParameter("auth:read unrelated:write"), want: []string{"auth:read"}},
				{name: "unauthorized", configured: []string{"auth:read"}, requested: scopeParameter("auth:write")},
				{name: "explicit empty", configured: []string{"auth:read"}, requested: scopeParameter(""), invalid: true},
				{name: "unconfigured empty", requested: scopeParameter(""), invalid: true},
				{name: "empty scope token", configured: []string{"auth:read"}, requested: scopeParameter("auth:read "), invalid: true},
				{name: "unconfigured omitted"},
				{name: "unconfigured explicit", requested: scopeParameter("auth:write")},
			} {
				t.Run(tc.name, func(t *testing.T) {
					ctx := context.Background()
					pg := srv.NewDatabase(t)
					// Open only this test's UUID database in TestMain's private container.
					db, err := bunconnect.OpenSQLDB(logging.TestingContext(), bunconnect.ConnectionOptions{DatabaseSourceName: pg.ConnString()})
					require.NoError(t, err)
					defer func() { _ = db.Close() }()
					require.NoError(t, sqlstorage.Migrate(ctx, db))
					storage := sqlstorage.New(db)
					client := auth.NewClient(auth.ClientOptions{Scopes: tc.configured})
					_, secret := client.GenerateNewSecret(auth.SecretCreate{})
					var clients []auth.StaticClient
					if static {
						clients = []auth.StaticClient{{ClientOptions: client.ClientOptions, Secrets: []string{secret}}}
					} else {
						require.NoError(t, storage.SaveClient(ctx, client))
					}
					key, err := rsa.GenerateKey(rand.Reader, 2048)
					require.NoError(t, err)
					router := chi.NewRouter()
					server := httptest.NewServer(router)
					defer server.Close()
					provider, err := oidc.NewOpenIDProvider(oidc.NewStorageFacade(storage, nil, key, clients...), sha256.Sum256([]byte("synthetic-oidc-crypto-key-for-tests-only")), server.URL, []string{server.URL}, "", nil)
					require.NoError(t, err)
					oidc.AddRoutes(router, provider, storage, nil)
					form := url.Values{"grant_type": {"client_credentials"}}
					if tc.requested != nil {
						form.Set("scope", *tc.requested)
					}
					// Assert the actual decoder distinction: omission is nil; scope=
					// invokes SpaceDelimitedArray.UnmarshalText and becomes []string{""}.
					decodeReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
					decodeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					decoded, err := op.ParseClientCredentialsRequest(decodeReq, provider.Decoder())
					require.NoError(t, err)
					if tc.requested == nil {
						require.Nil(t, decoded.Scope)
					} else {
						require.Equal(t, strings.Split(*tc.requested, " "), []string(decoded.Scope))
					}
					req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/oauth/token", strings.NewReader(form.Encode()))
					require.NoError(t, err)
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					req.SetBasicAuth(client.Id, secret)
					res, err := server.Client().Do(req)
					require.NoError(t, err)
					defer func() { _ = res.Body.Close() }()
					if tc.invalid {
						require.Equal(t, http.StatusBadRequest, res.StatusCode)
						var response map[string]any
						require.NoError(t, json.NewDecoder(res.Body).Decode(&response))
						require.Equal(t, "invalid_scope", response["error"])
						require.NotContains(t, response, "access_token")
						require.NotContains(t, response, "refresh_token")
						count, err := db.NewSelect().Model(&auth.AccessToken{}).Count(ctx)
						require.NoError(t, err)
						require.Zero(t, count, "invalid scope must not issue a token")
						return
					}
					require.Equal(t, http.StatusOK, res.StatusCode)
					var response struct {
						AccessToken string `json:"access_token"`
					}
					require.NoError(t, json.NewDecoder(res.Body).Decode(&response))
					claims := jwt.MapClaims{}
					_, err = jwt.ParseWithClaims(response.AccessToken, claims, func(token *jwt.Token) (any, error) {
						require.Equal(t, jwt.SigningMethodRS256, token.Method)
						return &key.PublicKey, nil
					})
					require.NoError(t, err)
					scope, ok := claims["scope"].(string)
					require.True(t, ok, "JWT must carry its granted scopes as a string")
					require.ElementsMatch(t, tc.want, strings.Fields(scope))
				})
			}
		})
	}
}

func scopeParameter(value string) *string { return &value }
