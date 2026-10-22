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
	"time"

	auth "github.com/formancehq/auth/pkg"
	"github.com/formancehq/auth/pkg/storage"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"github.com/zitadel/oidc/v2/pkg/op"
)

// Unexpected storage calls fail through the embedded interface. Each test owns
// its data; the HTTP test uses a recorder without opening a TCP listener.
type introspectionStorage struct {
	Storage
	clients     map[string]*auth.Client
	tokens      map[string]*auth.AccessToken
	users       map[string]*auth.User
	userLookups []string
}

func (s *introspectionStorage) FindClient(_ context.Context, id string) (*auth.Client, error) {
	if client, ok := s.clients[id]; ok {
		return client, nil
	}
	return nil, storage.ErrNotFound
}

func (s *introspectionStorage) SaveAccessToken(_ context.Context, token *auth.AccessToken) error {
	s.tokens[token.ID] = token
	return nil
}

func (s *introspectionStorage) FindAccessToken(_ context.Context, id string) (*auth.AccessToken, error) {
	if token, ok := s.tokens[id]; ok {
		return token, nil
	}
	return nil, storage.ErrNotFound
}

func (s *introspectionStorage) FindUser(_ context.Context, id string) (*auth.User, error) {
	s.userLookups = append(s.userLookups, id)
	if user, ok := s.users[id]; ok {
		return user, nil
	}
	return nil, storage.ErrNotFound
}

func TestSetIntrospectionFromTokenExpiration(t *testing.T) {
	for _, test := range []struct {
		name       string
		expiration time.Time
		active     bool
	}{
		{name: "unexpired", expiration: time.Now().Add(time.Hour), active: true},
		{name: "expired", expiration: time.Now().Add(-time.Hour), active: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Use an existing user to isolate expiration from the machine-token bug.
			store := &introspectionStorage{
				tokens: map[string]*auth.AccessToken{"token": {
					ID: "token", UserID: "user", ApplicationID: "owner",
					Audience: []string{"owner"}, Expiration: test.expiration,
				}},
				users: map[string]*auth.User{"user": {ID: "user"}},
			}
			facade := &storageFacade{Storage: store}
			var response oidc.IntrospectionResponse
			require.NoError(t, facade.SetIntrospectionFromToken(context.Background(), &response, "token", "user", "owner"))
			require.Equal(t, test.active, response.Active)
		})
	}
}

func TestSetIntrospectionFromTokenClaimsAndAccess(t *testing.T) {
	for _, test := range []struct {
		name       string
		requester  string
		trusted    bool
		userID     string
		wantError  string
		wantLookup bool
	}{
		{name: "machine owner", requester: "owner"},
		{name: "trusted machine reader", requester: "reader", trusted: true},
		{name: "untrusted other client", requester: "reader", wantError: "token is not valid for this client"},
		{name: "unknown client", requester: "unknown", wantError: "not found"},
		{name: "user owner", requester: "owner", userID: "user", wantLookup: true},
		{name: "missing user", requester: "owner", userID: "missing", wantError: "retrieving user: missing: not found", wantLookup: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &introspectionStorage{
				clients: map[string]*auth.Client{"reader": auth.NewClient(auth.ClientOptions{Id: "reader", Trusted: test.trusted})},
				tokens: map[string]*auth.AccessToken{"token": {
					ID: "token", UserID: test.userID, ApplicationID: "owner", Audience: []string{"owner"},
					Expiration: time.Now().Add(time.Hour), Scopes: []string{"openid", "email", "auth:read"},
				}},
				users: map[string]*auth.User{"user": {ID: "user", Email: "user@example.invalid"}},
			}
			facade := &storageFacade{Storage: store}
			var response oidc.IntrospectionResponse
			err := facade.SetIntrospectionFromToken(context.Background(), &response, "token", test.userID, test.requester)
			if test.wantLookup {
				require.Equal(t, []string{test.userID}, store.userLookups)
			} else {
				require.Empty(t, store.userLookups)
			}
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
				require.False(t, response.Active)
				return
			}
			require.NoError(t, err)
			require.True(t, response.Active)
			require.Equal(t, "owner", response.ClientID)
			require.Equal(t, oidc.SpaceDelimitedArray{"openid", "email", "auth:read"}, response.Scope)
			if test.userID == "" {
				require.Empty(t, response.Subject)
				require.Empty(t, response.Email)
				require.False(t, bool(response.EmailVerified))
			} else {
				require.Equal(t, "user", response.Subject)
				require.Equal(t, "user@example.invalid", response.Email)
				require.True(t, bool(response.EmailVerified))
			}
		})
	}
}

// Regression for Heal s5-own-token-introspects-inactive-1: issue and introspect
// a real signed client_credentials JWT through the production OAuth handlers.
func TestClientCredentialsIntrospection(t *testing.T) {
	const issuer = "http://introspection.local"
	ctx := op.ContextWithIssuer(context.Background(), issuer)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	client := auth.NewClient(auth.ClientOptions{Id: "machine", Scopes: auth.Array[string]{"auth:read", "auth:write"}})
	_, secret := client.GenerateNewSecret(auth.SecretCreate{})
	store := &introspectionStorage{
		clients: map[string]*auth.Client{client.Id: client},
		tokens:  map[string]*auth.AccessToken{},
	}
	facade := NewStorageFacade(store, nil, key)
	provider, err := NewOpenIDProvider(facade, sha256.Sum256([]byte("synthetic-oidc-crypto-key-for-tests-only")), issuer, nil, "", nil)
	require.NoError(t, err)
	post := func(path string, form url.Values, password string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, issuer+path, strings.NewReader(form.Encode())).WithContext(ctx)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(client.Id, password)
		rec := httptest.NewRecorder()
		provider.HttpHandler().ServeHTTP(rec, req)
		return rec
	}
	issued := post("/oauth/token", url.Values{"grant_type": {"client_credentials"}, "scope": {"auth:read auth:write"}}, secret)
	require.Equal(t, http.StatusOK, issued.Code, issued.Body.String())
	var tokenResponse oidc.AccessTokenResponse
	require.NoError(t, json.Unmarshal(issued.Body.Bytes(), &tokenResponse))
	require.NotEmpty(t, tokenResponse.AccessToken)
	claims, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, tokenResponse.AccessToken, provider.AccessTokenVerifier(ctx))
	require.NoError(t, err)
	require.Empty(t, store.tokens[claims.JWTID].UserID)
	form := url.Values{"token": {tokenResponse.AccessToken}}
	denied := post("/oauth/introspect", form, "wrong-secret")
	require.Equal(t, http.StatusUnauthorized, denied.Code)
	response := post("/oauth/introspect", form, secret)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	require.Equal(t, map[string]any{
		"active": true, "client_id": client.Id, "scope": "auth:read auth:write",
	}, body)
	require.Empty(t, store.userLookups)
}
