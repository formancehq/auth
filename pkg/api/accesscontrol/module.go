package accesscontrol

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/numary/go-libs/sharedlogging"
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

func authenticationMiddleware(o op.OpenIDProvider) func(h http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				authHeader := r.Header.Get("authorization")
				if authHeader == "" {
					sharedlogging.GetLogger(r.Context()).Debugf("missing authorization header: %s", r.URL)
					h.ServeHTTP(w, r)
					return
				}

				if !strings.HasPrefix(strings.ToLower(authHeader), strings.ToLower(oidc.PrefixBearer)) {
					sharedlogging.GetLogger(r.Context()).Debugf("malformed authorization header: %s", r.URL)
					h.ServeHTTP(w, r)
					return
				}

				token := strings.TrimPrefix(authHeader, oidc.PrefixBearer)

				claims, err := op.VerifyAccessToken(r.Context(), token, o.AccessTokenVerifier())
				if err != nil {
					sharedlogging.GetLogger(r.Context()).Debugf("could not verify access token: %s: %s", r.URL, err)
					h.ServeHTTP(w, r)
					return
				}

				fmt.Printf("CLAIMS: %+v\n", claims)
				h.ServeHTTP(w, r)
			})
	}
}
