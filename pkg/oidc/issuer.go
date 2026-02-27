package oidc

import (
	"net/http"
	"net/url"
)

// HostFromRequest returns the effective host, preferring X-Forwarded-Host over Host.
func HostFromRequest(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		return fwd
	}
	return r.Host
}

// IssuerForHost returns the trusted issuer matching the given host, or the default.
func IssuerForHost(host, defaultIssuer string, trustedIssuers []string) string {
	for _, issuer := range trustedIssuers {
		u, err := url.Parse(issuer)
		if err == nil && u.Host == host {
			return issuer
		}
	}
	return defaultIssuer
}

// HostFromIssuer extracts the host component from an issuer URL.
func HostFromIssuer(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return ""
	}
	return u.Host
}
