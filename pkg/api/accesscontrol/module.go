package accesscontrol

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/formancehq/auth/pkg/api"
	"github.com/gorilla/mux"
	"github.com/zitadel/oidc/pkg/oidc"
	"github.com/zitadel/oidc/pkg/op"
	"go.uber.org/fx"
)

func Module() fx.Option {
	return fx.Options(
		fx.Invoke(func(router *mux.Router, o op.OpenIDProvider) error {
			return router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
				route.Handler(
					authenticationMiddleware(o)(route.GetHandler()),
				)
				return nil
			})
		}),
	)
}

var (
	ErrMissingAuthHeader   = "missing authorization header"
	ErrMalformedAuthHeader = "malformed authorization header"
	ErrVerifyAuthToken     = "could not verify access token"
)

func authenticationMiddleware(o op.OpenIDProvider) func(h http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.URL.String(), api.PathClients) &&
					!strings.HasPrefix(r.URL.String(), api.PathScopes) {
					h.ServeHTTP(w, r)
					return
				}

				authHeader := r.Header.Get("authorization")
				if authHeader == "" {
					http.Error(w, ErrMissingAuthHeader, http.StatusUnauthorized)
					return
				}

				if !strings.HasPrefix(strings.ToLower(authHeader), strings.ToLower(oidc.PrefixBearer)) {
					http.Error(w, ErrMalformedAuthHeader, http.StatusUnauthorized)
					return
				}

				token := strings.TrimPrefix(authHeader, oidc.PrefixBearer)

				claims, err := op.VerifyAccessToken(r.Context(), token, o.AccessTokenVerifier())
				if err != nil {
					http.Error(w, ErrVerifyAuthToken, http.StatusUnauthorized)
					return
				}

				fmt.Printf("CLAIMS: %+v\n", claims)
				h.ServeHTTP(w, r)
			})
	}
}