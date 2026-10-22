//go:build it

package oidc_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/formancehq/auth/pkg"
	"github.com/formancehq/auth/pkg/oidc"
	"github.com/formancehq/auth/pkg/storage"
	"github.com/formancehq/auth/pkg/storage/sqlstorage"
	"github.com/google/uuid"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	zoidc "github.com/zitadel/oidc/v2/pkg/oidc"
	"github.com/zitadel/oidc/v2/pkg/op"
)

func TestEndSession(t *testing.T) {
	withServer(t, func(_ *mockoidc.MockOIDC, store *sqlstorage.Storage, issuer string, provider op.OpenIDProvider) {
		ctx := op.ContextWithIssuer(t.Context(), issuer)
		httpClient := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		newClient := func() (*auth.Client, string) {
			client := auth.NewClient(auth.ClientOptions{Scopes: auth.Array[string]{"openid"}})
			_, secret := client.GenerateNewSecret(auth.SecretCreate{})
			require.NoError(t, store.SaveClient(ctx, client))
			return client, secret
		}
		owner, secret := newClient()
		other, otherSecret := newClient()
		post := func(path string, form url.Values, clientID, password string) []byte {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+path, strings.NewReader(form.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(clientID, password)
			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
			return body
		}
		type token struct{ raw, id, clientID, secret string }
		mint := func(clientID, password string) token {
			var response zoidc.AccessTokenResponse
			require.NoError(t, json.Unmarshal(post("/oauth/token", url.Values{"grant_type": {"client_credentials"}}, clientID, password), &response))
			claims := new(zoidc.AccessTokenClaims)
			_, err := zoidc.ParseToken(response.AccessToken, claims)
			require.NoError(t, err)
			row, err := store.FindAccessToken(ctx, claims.JWTID)
			require.NoError(t, err)
			require.Empty(t, row.UserID)
			return token{response.AccessToken, claims.JWTID, clientID, password}
		}
		active := func(tok token) bool {
			var response zoidc.IntrospectionResponse
			require.NoError(t, json.Unmarshal(post("/oauth/introspect", url.Values{"token": {tok.raw}}, tok.clientID, tok.secret), &response))
			return response.Active
		}
		logout := func(method string, form url.Values) (int, string) {
			endpoint := issuer + "/end_session"
			var body io.Reader
			if method == http.MethodGet {
				endpoint += "?" + form.Encode()
			} else {
				body = strings.NewReader(form.Encode())
			}
			// No Authorization header, cookies, or client secret on logout.
			req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
			require.NoError(t, err)
			if method == http.MethodPost {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			return resp.StatusCode, resp.Header.Get("Location")
		}

		subjectlessHint, err := op.CreateIDToken(ctx, issuer, &auth.AuthRequest{ApplicationID: owner.Id, AuthTime: time.Now()}, time.Hour, "", "", provider.Storage(), oidc.NewClientFacade(owner, nil))
		require.NoError(t, err)
		for _, test := range []struct {
			name, method string
			form         url.Values
		}{
			{"GET", http.MethodGet, url.Values{"client_id": {owner.Id}}},
			{"POST", http.MethodPost, url.Values{"client_id": {owner.Id}}},
			{"empty_hint", http.MethodGet, url.Values{"client_id": {owner.Id}, "id_token_hint": {""}}},
			{"signed_subjectless_hint", http.MethodPost, url.Values{"client_id": {owner.Id}, "id_token_hint": {subjectlessHint}}},
			{"no_parameters", http.MethodGet, nil},
		} {
			t.Run("unproven_session/"+test.name, func(t *testing.T) {
				tokens := []token{mint(owner.Id, secret), mint(owner.Id, secret), mint(other.Id, otherSecret)}
				for _, tok := range tokens {
					require.True(t, active(tok))
				}
				status, _ := logout(test.method, test.form)
				for i, tok := range tokens {
					_, err := store.FindAccessToken(ctx, tok.id)
					isActive := active(tok)
					t.Logf("token %d: end_session=%d registry_present=%t introspection_active=%t", i, status, err == nil, isActive)
					assert.NoError(t, err)
					assert.True(t, isActive)
				}
				assert.Equal(t, http.StatusBadRequest, status)
			})
		}

		t.Run("proven_user_session", func(t *testing.T) {
			user := &auth.User{ID: uuid.NewString(), Subject: uuid.NewString()}
			require.NoError(t, store.SaveUser(ctx, user))
			request := &auth.AuthRequest{ApplicationID: owner.Id, UserID: user.ID, AuthTime: time.Now()}
			var ids []string
			for range 2 {
				id, _, err := provider.Storage().CreateAccessToken(ctx, request)
				require.NoError(t, err)
				ids = append(ids, id)
			}
			control := mint(owner.Id, secret)
			otherUser := &auth.User{ID: uuid.NewString(), Subject: uuid.NewString()}
			require.NoError(t, store.SaveUser(ctx, otherUser))
			request.UserID = otherUser.ID
			otherUserTokenID, _, err := provider.Storage().CreateAccessToken(ctx, request)
			require.NoError(t, err)
			request.UserID = user.ID
			request.ApplicationID = other.Id
			otherClientTokenID, _, err := provider.Storage().CreateAccessToken(ctx, request)
			require.NoError(t, err)
			request.ApplicationID = owner.Id
			hint, err := op.CreateIDToken(ctx, issuer, request, time.Hour, "", "", provider.Storage(), oidc.NewClientFacade(owner, nil))
			require.NoError(t, err)
			for range 2 {
				status, location := logout(http.MethodGet, url.Values{"id_token_hint": {hint}, "client_id": {owner.Id}, "state": {"logout-state"}})
				require.Equal(t, http.StatusFound, status)
				require.Equal(t, "/logged-out?state=logout-state", location)
			}
			for _, id := range ids {
				_, err := store.FindAccessToken(ctx, id)
				require.ErrorIs(t, err, storage.ErrNotFound)
			}
			_, err = store.FindAccessToken(ctx, otherClientTokenID)
			require.NoError(t, err)
			_, err = store.FindAccessToken(ctx, otherUserTokenID)
			require.NoError(t, err)
			require.True(t, active(control), "user logout must preserve machine tokens of the same client")
		})
	})
}
