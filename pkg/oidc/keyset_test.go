package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/formancehq/auth/pkg/delegatedauth"
	"github.com/stretchr/testify/require"
	"gopkg.in/go-jose/go-jose.v2"
)

func TestRemoteKeySetRefreshesOnUnknownKeyID(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	oldJWK := jose.JSONWebKey{Key: &oldKey.PublicKey, KeyID: "old", Use: "sig"}
	newJWK := jose.JSONWebKey{Key: &newKey.PublicKey, KeyID: "new", Use: "sig"}
	var jwksRequests atomic.Int32
	serveNewKey := atomic.Bool{}

	server := httptest.NewServer(nil)
	defer server.Close()

	// The discovery response needs the server URL, which is only known after startup.
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": server.URL, "jwks_uri": server.URL + "/jwks"})
		case "/jwks":
			jwksRequests.Add(1)
			keys := []jose.JSONWebKey{oldJWK}
			if serveNewKey.Load() {
				keys = []jose.JSONWebKey{newJWK}
			}
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: keys})
		}
	})

	keySet, err := ReadKeySet(http.DefaultClient, context.Background(), delegatedauth.Config{Issuer: server.URL})
	require.NoError(t, err)
	require.Equal(t, int32(1), jwksRequests.Load())

	serveNewKey.Store(true)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: newKey, KeyID: "new"}}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	serialized, err := signer.Sign([]byte("payload"))
	require.NoError(t, err)
	jws, err := jose.ParseSigned(serialized.FullSerialize())
	require.NoError(t, err)

	payload, err := keySet.VerifySignature(context.Background(), jws)
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), payload)
	require.Equal(t, int32(2), jwksRequests.Load())
}
