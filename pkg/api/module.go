package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/formancehq/go-libs/v3/service"

	"github.com/formancehq/go-libs/v3/api"
	"github.com/formancehq/go-libs/v3/health"
	"github.com/formancehq/go-libs/v3/httpserver"
	"github.com/formancehq/go-libs/v3/logging"
	authoidc "github.com/formancehq/auth/pkg/oidc"
	"github.com/zitadel/oidc/v2/pkg/op"
	"go.uber.org/fx"
)

func CreateRootRouter(
	logger logging.Logger,
	defaultIssuer string,
	trustedIssuers []string,
	debug bool,
) chi.Router {
	rootRouter := chi.NewRouter()
	rootRouter.Use(service.OTLPMiddleware("auth", debug))
	rootRouter.Use(httpserver.LoggerMiddleware(logger))
	rootRouter.Use(func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			handler.ServeHTTP(w, r)
		})
	})
	rootRouter.Use(func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := authoidc.HostFromRequest(r)
			issuer := authoidc.IssuerForHost(host, defaultIssuer, trustedIssuers)
			handler.ServeHTTP(w, r.WithContext(
				op.ContextWithIssuer(r.Context(), issuer),
			))
		})
	})
	return rootRouter
}

func addInfoRoute(router chi.Router, serviceInfo api.ServiceInfo) {
	router.Get("/_info", api.InfoHandler(serviceInfo))
}

func Module(addr, defaultIssuer string, trustedIssuers []string, serviceInfo api.ServiceInfo, debug bool) fx.Option {
	return fx.Options(
		health.Module(),
		fx.Supply(serviceInfo),
		fx.Provide(func(logger logging.Logger) chi.Router {
			return CreateRootRouter(logger, defaultIssuer, trustedIssuers, debug)
		}),
		fx.Invoke(
			addInfoRoute,
			addClientRoutes,
			addUserRoutes,
		),
		fx.Invoke(func(lc fx.Lifecycle, r chi.Router, healthController *health.HealthController, o op.OpenIDProvider) {
			finalRouter := chi.NewRouter()
			finalRouter.Get("/_healthcheck", healthController.Check)
			finalRouter.Mount("/", r)

			lc.Append(httpserver.NewHook(finalRouter, httpserver.WithAddress(addr)))
		}),
	)
}
