package accesscontrol

import (
	"fmt"
	"net/http"
	"os"
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

func authenticationMiddleware(o op.OpenIDProvider) func(h http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				f, _ := os.OpenFile("auth.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				defer func(f *os.File) {
					_ = f.Close()
				}(f)

				if !strings.HasPrefix(r.URL.String(), api.PathClients) &&
					!strings.HasPrefix(r.URL.String(), api.PathScopes) {
					_, _ = f.WriteString(fmt.Sprintf("OK: %s\n", r.URL))
					h.ServeHTTP(w, r)
					return
				}

				authHeader := r.Header.Get("authorization")
				if authHeader == "" {
					_, _ = f.WriteString(fmt.Sprintf("ERROR: missing authorization header: %s\n", r.URL))
					h.ServeHTTP(w, r)
					return
				}

				if !strings.HasPrefix(strings.ToLower(authHeader), strings.ToLower(oidc.PrefixBearer)) {
					_, _ = f.WriteString(fmt.Sprintf("ERROR: malformed authorization header: %s\n", r.URL))
					h.ServeHTTP(w, r)
					return
				}

				token := strings.TrimPrefix(authHeader, oidc.PrefixBearer)

				claims, err := op.VerifyAccessToken(r.Context(), token, o.AccessTokenVerifier())
				if err != nil {
					_, _ = f.WriteString(fmt.Sprintf("ERROR: could not verify access token: %s: %s\n", r.URL, err))
					h.ServeHTTP(w, r)
					return
				}

				_, _ = f.WriteString(fmt.Sprintf("CLAIMS: %s: %+v\n", r.URL, claims))
				h.ServeHTTP(w, r)
			})
	}
}
