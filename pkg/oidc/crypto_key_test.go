package oidc

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
	"github.com/formancehq/auth/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	zoidc "github.com/zitadel/oidc/v2/pkg/oidc"
	"github.com/zitadel/oidc/v2/pkg/op"
)

type cryptoKeyStorage struct{ introspectionStorage }

func (s *cryptoKeyStorage) DeleteAccessToken(_ context.Context, id string) error {
	delete(s.tokens, id)
	return nil
}

func (s *cryptoKeyStorage) FindRefreshToken(context.Context, string) (*auth.RefreshToken, error) {
	return nil, storage.ErrNotFound
}
func (s *cryptoKeyStorage) RevokeRefreshToken(context.Context, string, string) error {
	return storage.ErrNotFound
}

// Exercise production HTTP handlers with synthetic clients and in-memory token
// storage. No database, network listener, or external issuer is required.
func TestProviderRejectsArtifactsForgedWithPublicKey(t *testing.T) {
	const issuer = "http://crypto-key.local"
	ctx := op.ContextWithIssuer(t.Context(), issuer)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	client := auth.NewClient(auth.ClientOptions{Id: "machine", Scopes: auth.Array[string]{"auth:read"}})
	_, secret := client.GenerateNewSecret(auth.SecretCreate{})
	store := &cryptoKeyStorage{introspectionStorage: introspectionStorage{
		clients: map[string]*auth.Client{client.Id: client}, tokens: map[string]*auth.AccessToken{},
	}}
	provider, err := NewOpenIDProvider(NewStorageFacade(store, nil, key), sha256.Sum256([]byte("synthetic-oidc-crypto-key-for-tests-only")), issuer, nil, "", nil)
	require.NoError(t, err)
	post := func(path, token string) *httptest.ResponseRecorder {
		form := url.Values{"token": {token}}
		if path == "/oauth/token" {
			form = url.Values{"grant_type": {"client_credentials"}}
		}
		req := httptest.NewRequest(http.MethodPost, issuer+path, strings.NewReader(form.Encode())).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(client.Id, secret)
		rec := httptest.NewRecorder()
		provider.HttpHandler().ServeHTTP(rec, req)
		return rec
	}
	issued := post("/oauth/token", "")
	require.Equal(t, http.StatusOK, issued.Code, issued.Body.String())
	var token zoidc.AccessTokenResponse
	require.NoError(t, json.Unmarshal(issued.Body.Bytes(), &token))
	claims, err := op.VerifyAccessToken[*zoidc.AccessTokenClaims](ctx, token.AccessToken, provider.AccessTokenVerifier(ctx))
	require.NoError(t, err)
	introspect := func(raw string) bool {
		response := post("/oauth/introspect", raw)
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		var body zoidc.IntrospectionResponse
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
		return body.Active
	}
	require.True(t, introspect(token.AccessToken), "genuine JWT control")
	require.False(t, introspect("totally-invalid"), "invalid token control")
	forged, err := op.NewAESCrypto(sha256.Sum256([]byte("test"))).Encrypt(claims.JWTID + ":" + claims.Subject)
	require.NoError(t, err)
	forgedActive := introspect(forged)
	t.Logf("public-key forged artifact active=%v", forgedActive)
	assert.False(t, forgedActive, "public-key forged artifact must not be accepted")
	revoked := post("/revoke", forged)
	require.Equal(t, http.StatusOK, revoked.Code, revoked.Body.String())
	require.Contains(t, store.tokens, claims.JWTID, "forged artifact must not revoke the genuine token")
	require.True(t, introspect(token.AccessToken))
	// Another unknown key cannot produce a valid token either.
	other, err := op.NewAESCrypto(sha256.Sum256([]byte("synthetic-unrelated-key-for-tests-only"))).Encrypt(claims.JWTID + ":" + claims.Subject)
	require.NoError(t, err)
	require.False(t, introspect(other))
	for _, raw := range []string{forged, other} {
		req := httptest.NewRequest(http.MethodGet, issuer+"/userinfo", nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+raw)
		rec := httptest.NewRecorder()
		provider.HttpHandler().ServeHTTP(rec, req)
		require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, rec.Code, rec.Body.String())
	}
	// The provider's own opaque format must still work with the configured key.
	legitimate, err := provider.Crypto().Encrypt(claims.JWTID + ":" + claims.Subject)
	require.NoError(t, err)
	require.True(t, introspect(legitimate))
	require.Equal(t, http.StatusOK, post("/revoke", legitimate).Code)
	require.NotContains(t, store.tokens, claims.JWTID)
	// Revocation does not change the signature or expiry contract of issued JWTs.
	_, err = op.VerifyAccessToken[*zoidc.AccessTokenClaims](ctx, token.AccessToken, provider.AccessTokenVerifier(ctx))
	require.NoError(t, err)
}

func TestProviderRejectsUnconfiguredOrPublicCryptoKey(t *testing.T) {
	for _, key := range [][32]byte{{}, sha256.Sum256(nil), sha256.Sum256([]byte("test"))} {
		provider, err := NewOpenIDProvider(nil, key, "http://crypto-key.local", nil, "", nil)
		require.EqualError(t, err, "OIDC crypto key must be configured with non-public secret material")
		require.Nil(t, provider)
	}
}

func TestProviderCryptoKeyStabilityAndRotation(t *testing.T) {
	key := sha256.Sum256([]byte("synthetic-oidc-crypto-key-for-tests-only"))
	first, err := NewOpenIDProvider(nil, key, "http://crypto-key.local", nil, "", nil)
	require.NoError(t, err)
	second, err := NewOpenIDProvider(nil, key, "http://crypto-key.local", nil, "", nil)
	require.NoError(t, err)
	ciphertext, err := first.Crypto().Encrypt("synthetic-token:synthetic-user")
	require.NoError(t, err)
	plaintext, err := second.Crypto().Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, "synthetic-token:synthetic-user", plaintext)
	rotated, err := NewOpenIDProvider(nil, sha256.Sum256([]byte("synthetic-rotated-crypto-key-for-tests-only")), "http://crypto-key.local", nil, "", nil)
	require.NoError(t, err)
	plaintext, _ = rotated.Crypto().Decrypt(ciphertext)
	require.NotEqual(t, "synthetic-token:synthetic-user", plaintext)
}
