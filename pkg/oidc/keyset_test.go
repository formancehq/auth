package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
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

// A verifier can be descheduled after reading the cache and resume only after
// another verifier has completed the refresh. It must reuse that result.
func TestRemoteKeySetReusesRefreshAfterCacheLookup(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{})
	}))
	defer server.Close()
	keySet := &remoteKeySet{httpClient: server.Client(), jwksURI: server.URL}
	_, generation := keySet.cachedKeys()

	refreshed := make(chan error, 1)
	go func() {
		_, err := keySet.keysFromRemote(context.Background(), generation)
		refreshed <- err
	}()
	require.NoError(t, <-refreshed)
	_, err := keySet.keysFromRemote(context.Background(), generation)
	require.NoError(t, err)
	require.Equal(t, int32(1), requests.Load())
}

func TestRemoteKeySetRefreshSurvivesInitiatorCancellation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "new", Use: "sig"}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "new"}}, nil)
	require.NoError(t, err)
	signed, err := signer.Sign([]byte("payload"))
	require.NoError(t, err)
	jws, err := jose.ParseSigned(signed.FullSerialize())
	require.NoError(t, err)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-release:
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	keySet := &remoteKeySet{httpClient: server.Client(), jwksURI: server.URL}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() {
		_, err := keySet.VerifySignature(ctx, jws)
		first <- err
	}()
	<-started

	// Start a second waiter before cancelling the initiating exchange. Its Done
	// call marks that it has reached the shared refresh's cancellation select.
	waiting := make(chan struct{})
	liveCtx := &waiterContext{Context: context.Background(), waiting: waiting}
	second := make(chan error, 1)
	go func() {
		payload, err := keySet.VerifySignature(liveCtx, jws)
		if err == nil && string(payload) != "payload" {
			err = fmt.Errorf("unexpected payload %q", payload)
		}
		second <- err
	}()
	<-waiting
	cancel()
	require.ErrorIs(t, <-first, context.Canceled)

	unblock()
	require.NoError(t, <-second)
	require.Equal(t, int32(1), requests.Load())
}

type waiterContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *waiterContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}
