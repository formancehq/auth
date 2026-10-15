package oidc_test

import (
	"context"
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
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/require"
	zoidc "github.com/zitadel/oidc/v2/pkg/oidc"
	"github.com/zitadel/oidc/v2/pkg/op"
)

func TestRevocation(t *testing.T) {
	withServer(t, func(m *mockoidc.MockOIDC, db *sqlstorage.Storage, issuer string, provider op.OpenIDProvider) {
		ctx := op.ContextWithIssuer(context.Background(), issuer)
		newClient := func() (*auth.Client, string) {
			client := auth.NewClient(auth.ClientOptions{Scopes: auth.Array[string]{"openid", "offline_access"}})
			_, secret := client.GenerateNewSecret(auth.SecretCreate{})
			require.NoError(t, db.SaveClient(ctx, client))
			return client, secret
		}
		owner, ownerSecret := newClient()
		other, otherSecret := newClient()
		user := &auth.User{ID: uuid.NewString(), Subject: uuid.NewString()}
		require.NoError(t, db.SaveUser(ctx, user))
		httpClient := &http.Client{Timeout: 10 * time.Second}

		post := func(t *testing.T, path string, form url.Values, clientID, secret string) (int, []byte) {
			t.Helper()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+path, strings.NewReader(form.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(clientID, secret)
			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			return resp.StatusCode, body
		}
		userinfo := func(t *testing.T, token string, want int) {
			t.Helper()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/userinfo", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, want, resp.StatusCode)
		}
		// Login is skipped for the user-session fixture. Token persistence and JWT
		// signing still use the production storage facade and provider signing key.
		issue := func(t *testing.T, kind string) (token, accessID, accessJWT, refreshID string) {
			t.Helper()
			if kind == "user_access" || kind == "refresh" {
				req := &auth.AuthRequest{ApplicationID: owner.Id, UserID: user.ID, Scopes: auth.Array[string]{"openid", "offline_access"}, AuthTime: time.Now()}
				id, refresh, exp, err := provider.Storage().CreateAccessAndRefreshTokens(ctx, req, "")
				require.NoError(t, err)
				raw, err := op.CreateJWT(ctx, issuer, req, exp, id, oidc.NewClientFacade(owner, nil), provider.Storage())
				require.NoError(t, err)
				if kind == "refresh" {
					// Positive control: this refresh token actually mints tokens over
					// HTTP before we revoke the rotated token returned by the server.
					status, body := post(t, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, owner.Id, ownerSecret)
					require.Equal(t, http.StatusOK, status, string(body))
					var response zoidc.AccessTokenResponse
					require.NoError(t, json.Unmarshal(body, &response))
					require.NotEmpty(t, response.AccessToken)
					require.NotEmpty(t, response.RefreshToken)
					claims := new(zoidc.AccessTokenClaims)
					_, err = zoidc.ParseToken(response.AccessToken, claims)
					require.NoError(t, err)
					row, err := db.FindAccessToken(ctx, claims.JWTID)
					require.NoError(t, err)
					require.Equal(t, response.RefreshToken, row.RefreshTokenID)
					return response.RefreshToken, claims.JWTID, response.AccessToken, response.RefreshToken
				}
				return raw, id, raw, refresh
			}
			form := url.Values{"grant_type": {"client_credentials"}}
			if kind == "jwt_bearer" {
				assertion, err := m.Keypair.SignJWT(jwt.MapClaims{
					"iss": m.Issuer(), "sub": user.ID, "aud": issuer,
					"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "scope": "openid",
					// Assertion claims must not choose the token's owning client.
					"client_id": other.Id, "azp": other.Id,
				})
				require.NoError(t, err)
				form = url.Values{"grant_type": {string(zoidc.GrantTypeBearer)}, "assertion": {assertion}}
			}
			status, body := post(t, "/oauth/token", form, owner.Id, ownerSecret)
			require.Equal(t, http.StatusOK, status, string(body))
			var response zoidc.AccessTokenResponse
			require.NoError(t, json.Unmarshal(body, &response))
			require.NotEmpty(t, response.AccessToken)
			claims := new(zoidc.AccessTokenClaims)
			_, err := zoidc.ParseToken(response.AccessToken, claims)
			require.NoError(t, err)
			row, err := db.FindAccessToken(ctx, claims.JWTID)
			require.NoError(t, err)
			require.Equal(t, owner.Id, row.ApplicationID)
			return response.AccessToken, claims.JWTID, response.AccessToken, ""
		}

		t.Run("refresh_cascade", func(t *testing.T) {
			token, accessID, accessJWT, _ := issue(t, "refresh")
			_, unrelatedID, unrelatedJWT, unrelatedRefresh := issue(t, "user_access")
			// Add a second outstanding access token for this refresh token to
			// verify that revocation removes every derived row, not just one.
			row, err := db.FindAccessToken(ctx, accessID)
			require.NoError(t, err)
			row.ID = uuid.NewString()
			require.NoError(t, db.SaveAccessToken(ctx, row))
			refresh, err := db.FindRefreshToken(ctx, token)
			require.NoError(t, err)
			extraJWT, err := op.CreateJWT(ctx, issuer, auth.NewRefreshTokenRequest(*refresh), row.Expiration, row.ID, oidc.NewClientFacade(owner, nil), provider.Storage())
			require.NoError(t, err)
			userinfo(t, extraJWT, http.StatusOK)
			status, body := post(t, "/revoke", url.Values{"token": {token}}, owner.Id, ownerSecret)
			require.Equal(t, http.StatusOK, status, string(body))
			for _, id := range []string{accessID, row.ID} {
				_, err = db.FindAccessToken(ctx, id)
				require.ErrorIs(t, err, storage.ErrNotFound)
			}
			userinfo(t, accessJWT, http.StatusForbidden)
			userinfo(t, extraJWT, http.StatusForbidden)
			_, err = db.FindAccessToken(ctx, unrelatedID)
			require.NoError(t, err)
			_, err = db.FindRefreshToken(ctx, unrelatedRefresh)
			require.NoError(t, err)
			userinfo(t, unrelatedJWT, http.StatusOK)
		})

		t.Run("refresh_with_access_hint_and_decryptable_uuid", func(t *testing.T) {
			token, accessID, accessJWT, _ := issue(t, "refresh")
			refresh, err := db.FindRefreshToken(ctx, token)
			require.NoError(t, err)
			var ambiguousID string
			for range 4096 {
				candidate := uuid.NewString()
				decoded, err := provider.Crypto().Decrypt(candidate)
				if err == nil && strings.Count(decoded, ":") == 1 {
					ambiguousID = candidate
					break
				}
			}
			require.NotEmpty(t, ambiguousID, "fixture must exercise the library's opaque-token decoding ambiguity")
			// Use a UUID with the same shape as issued refresh tokens that the
			// library would otherwise misidentify as an encrypted access token.
			refresh.ID = ambiguousID
			require.NoError(t, db.SaveRefreshToken(ctx, refresh))
			require.NoError(t, db.DeleteRefreshToken(ctx, token))
			row, err := db.FindAccessToken(ctx, accessID)
			require.NoError(t, err)
			row.RefreshTokenID = ambiguousID
			require.NoError(t, db.DeleteAccessToken(ctx, accessID))
			require.NoError(t, db.SaveAccessToken(ctx, row))
			status, body := post(t, "/revoke", url.Values{"token": {ambiguousID}, "token_type_hint": {"access_token"}}, owner.Id, ownerSecret)
			require.Equal(t, http.StatusOK, status, string(body))
			_, err = db.FindRefreshToken(ctx, ambiguousID)
			require.ErrorIs(t, err, storage.ErrNotFound)
			_, err = db.FindAccessToken(ctx, accessID)
			require.ErrorIs(t, err, storage.ErrNotFound)
			userinfo(t, accessJWT, http.StatusForbidden)
			status, body = post(t, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {ambiguousID}}, owner.Id, ownerSecret)
			require.Equal(t, http.StatusBadRequest, status, string(body))
			require.Contains(t, string(body), "invalid_grant")
		})

		// RFC 7009: hints are optional, incorrect/unknown hints must not prevent
		// lookup, and an invalid or already revoked token still returns HTTP 200.
		for _, kind := range []string{"client_credentials", "user_access", "refresh", "jwt_bearer"} {
			for _, hint := range []string{"", "access_token", "refresh_token", "unknown_hint"} {
				name := hint
				if name == "" {
					name = "no_hint"
				}
				t.Run(kind+"/"+name, func(t *testing.T) {
					token, accessID, accessJWT, refreshID := issue(t, kind)
					if kind != "client_credentials" {
						userinfo(t, accessJWT, http.StatusOK)
					}
					form := url.Values{"token": {token}}
					if hint != "" {
						form.Set("token_type_hint", hint)
					}
					status, body := post(t, "/revoke", form, owner.Id, ownerSecret)
					require.Equal(t, http.StatusOK, status, string(body))
					_, err := db.FindAccessToken(ctx, accessID)
					require.ErrorIs(t, err, storage.ErrNotFound)
					if kind == "refresh" {
						_, err = db.FindRefreshToken(ctx, refreshID)
						require.ErrorIs(t, err, storage.ErrNotFound)
						status, body = post(t, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshID}}, owner.Id, ownerSecret)
						require.Equal(t, http.StatusBadRequest, status, string(body))
						require.Contains(t, string(body), "invalid_grant")
					} else if refreshID != "" {
						_, err = db.FindRefreshToken(ctx, refreshID)
						require.NoError(t, err, "revoking an access token must preserve its refresh token")
					}
					if kind != "client_credentials" {
						userinfo(t, accessJWT, http.StatusForbidden)
					}
					status, body = post(t, "/revoke", form, owner.Id, ownerSecret)
					require.Equal(t, http.StatusOK, status, string(body))
				})
			}
		}

		for _, kind := range []string{"client_credentials", "user_access", "refresh", "jwt_bearer"} {
			t.Run("other_client/"+kind, func(t *testing.T) {
				token, accessID, accessJWT, refreshID := issue(t, kind)
				for _, hint := range []string{"", "access_token", "refresh_token"} {
					status, body := post(t, "/revoke", url.Values{"token": {token}, "token_type_hint": {hint}}, other.Id, otherSecret)
					require.Equal(t, http.StatusUnauthorized, status, string(body))
					require.Contains(t, string(body), "invalid_client")
					_, err := db.FindAccessToken(ctx, accessID)
					require.NoError(t, err, "another client must not delete the access token")
					if refreshID != "" {
						_, err = db.FindRefreshToken(ctx, refreshID)
						require.NoError(t, err, "another client must not delete the refresh token")
					}
				}
				status, _ := post(t, "/revoke", url.Values{"token": {token}}, owner.Id, "wrong-secret")
				require.Equal(t, http.StatusUnauthorized, status)
				if kind != "client_credentials" {
					userinfo(t, accessJWT, http.StatusOK)
				}
			})
		}
		t.Run("unknown_token", func(t *testing.T) {
			for _, hint := range []string{"", "access_token", "refresh_token", "unknown_hint"} {
				status, body := post(t, "/revoke", url.Values{"token": {"unknown-token"}, "token_type_hint": {hint}}, owner.Id, ownerSecret)
				require.Equal(t, http.StatusOK, status, string(body))
			}
		})
	})
}
