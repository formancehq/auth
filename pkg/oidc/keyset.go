package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/formancehq/auth/pkg/delegatedauth"
	"github.com/zitadel/oidc/v2/pkg/client"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"gopkg.in/go-jose/go-jose.v2"
)

func ReadKeySet(httpClient *http.Client, ctx context.Context, configuration delegatedauth.Config) (oidc.KeySet, error) {
	discoveryConfiguration, err := client.Discover(configuration.Issuer, httpClient)
	if err != nil {
		return nil, err
	}

	keySet := &remoteKeySet{
		httpClient: httpClient,
		jwksURI:    discoveryConfiguration.JwksURI,
	}
	if _, err := keySet.keysFromRemote(ctx); err != nil {
		return nil, err
	}
	return keySet, nil
}

// remoteKeySet caches the external provider's keys and refreshes them when a
// token refers to a key ID that is not in the cache. Refreshes are coalesced so
// a rotation cannot cause one JWKS request per concurrent token exchange.
type remoteKeySet struct {
	httpClient *http.Client
	jwksURI    string

	mu       sync.Mutex
	keys     jose.JSONWebKeySet
	inflight *keySetRefresh
}

type keySetRefresh struct {
	done chan struct{}
	keys jose.JSONWebKeySet
	err  error
}

func (r *remoteKeySet) VerifySignature(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	keyID, alg := oidc.GetKeyIDAndAlg(jws)
	keys := r.cachedKeys()

	key, err := oidc.FindMatchingKey(keyID, oidc.KeyUseSignature, alg, keys...)
	if err == nil {
		payload, verifyErr := jws.Verify(&key)
		if payload != nil {
			return payload, nil
		}
		if key.KeyID == keyID {
			return nil, fmt.Errorf("signature verification failed: %w", verifyErr)
		}
	}

	remoteKeys, err := r.keysFromRemote(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch key for signature validation: %w", err)
	}
	key, err = oidc.FindMatchingKey(keyID, oidc.KeyUseSignature, alg, remoteKeys.Keys...)
	if err != nil {
		return nil, fmt.Errorf("unable to validate signature: %w", err)
	}
	payload, err := jws.Verify(&key)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	return payload, nil
}

func (r *remoteKeySet) cachedKeys() []jose.JSONWebKey {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.keys.Keys
}

func (r *remoteKeySet) keysFromRemote(ctx context.Context) (jose.JSONWebKeySet, error) {
	r.mu.Lock()
	if r.inflight == nil {
		r.inflight = &keySetRefresh{done: make(chan struct{})}
		go r.refresh(ctx, r.inflight)
	}
	inflight := r.inflight
	r.mu.Unlock()

	select {
	case <-ctx.Done():
		return jose.JSONWebKeySet{}, ctx.Err()
	case <-inflight.done:
		return inflight.keys, inflight.err
	}
}

func (r *remoteKeySet) refresh(ctx context.Context, refresh *keySetRefresh) {
	keys, err := r.fetchRemoteKeys(ctx)

	r.mu.Lock()
	if err == nil {
		r.keys = keys
	}
	refresh.keys = keys
	refresh.err = err
	close(refresh.done)
	r.inflight = nil
	r.mu.Unlock()
}

func (r *remoteKeySet) fetchRemoteKeys(ctx context.Context) (jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.jwksURI, nil)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	rsp, err := r.httpClient.Do(req)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode < http.StatusOK || rsp.StatusCode >= http.StatusMultipleChoices {
		return jose.JSONWebKeySet{}, fmt.Errorf("JWKS endpoint returned status %s", rsp.Status)
	}

	var keySet jose.JSONWebKeySet
	if err := json.NewDecoder(rsp.Body).Decode(&keySet); err != nil {
		return jose.JSONWebKeySet{}, err
	}
	return keySet, nil
}
