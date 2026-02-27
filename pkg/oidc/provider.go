package oidc

import (
	"crypto/sha256"
	"net/http"
	"net/url"
	"time"

	"github.com/zitadel/oidc/v2/pkg/oidc"
	"github.com/zitadel/oidc/v2/pkg/op"
	"golang.org/x/text/language"
	"gopkg.in/go-jose/go-jose.v2"
)

const (
	pathLoggedOut = "/logged-out"
)

type verifier struct {
	issuer          string
	mat             time.Duration
	offset          time.Duration
	jsonWebKeySet   jose.JSONWebKeySet
	delegatedIssuer string
}

func (v verifier) DelegatedIssuer() string {
	return v.delegatedIssuer
}

func (v verifier) JSONWebKeySet() jose.JSONWebKeySet {
	return v.jsonWebKeySet
}

func (v verifier) Issuer() string {
	return v.issuer
}

func (v verifier) MaxAgeIAT() time.Duration {
	return v.mat
}

func (v verifier) Offset() time.Duration {
	return v.offset
}

type provider struct {
	op.OpenIDProvider
	delegatedIssuerJsonWebKeySet jose.JSONWebKeySet
	delegatedIssuer              string
	trustedIssuers               []string
}

func (p provider) JWTProfileVerifier(issuer string) JWTProfileVerifier {
	return &verifier{
		issuer:          issuer,
		delegatedIssuer: p.delegatedIssuer,
		mat:             time.Hour,
		offset:          0,
		jsonWebKeySet:   p.delegatedIssuerJsonWebKeySet,
	}
}

var _ JWTAuthorizationGrantExchanger = (*provider)(nil)

func NewOpenIDProvider(storage op.Storage, issuer string, trustedIssuers []string, delegatedIssuer string, delegatedIssuerJsonWebKeySet *jose.JSONWebKeySet) (op.OpenIDProvider, error) {
	var p op.OpenIDProvider

	parsedIssuer, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}

	interceptors := make([]op.Option, 0)
	if delegatedIssuer != "" {
		interceptors = append(interceptors, op.WithHttpInterceptors(func(handler http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Intercept token requests with grant_type of type bearer assertion
				// as the library does not implement what we needs
				if r.URL.Path == op.DefaultEndpoints.Token.Relative() &&
					r.FormValue("grant_type") == string(oidc.GrantTypeBearer) {
					grantTypeBearer(&provider{
						trustedIssuers:               trustedIssuers,
						OpenIDProvider:               p,
						delegatedIssuerJsonWebKeySet: *delegatedIssuerJsonWebKeySet,
						delegatedIssuer:              delegatedIssuer,
					}).ServeHTTP(w, r)
					return
				}
				handler.ServeHTTP(w, r)
			})

		}))
	}

	if parsedIssuer.Scheme == "http" {
		interceptors = append(interceptors, op.WithAllowInsecure())
	}

	// Use NewDynamicOpenIDProvider so ZITADEL reads the issuer from r.Host
	// (which is set by the chi middleware based on trusted issuers) instead
	// of using a static issuer string.
	p, err = op.NewDynamicOpenIDProvider(parsedIssuer.Path, &op.Config{
		CryptoKey:                sha256.Sum256([]byte("test")),
		DefaultLogoutRedirectURI: pathLoggedOut,
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   true,
		SupportedUILocales:       []language.Tag{language.English},
	}, storage, interceptors...)
	return p, err
}
