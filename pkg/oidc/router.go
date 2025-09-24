package oidc

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/trace"

	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/op"
)

const AuthorizeCallbackPath = "/authorize/callback"

func AddRoutes(r chi.Router, provider op.OpenIDProvider, storage Storage, relyingParty rp.RelyingParty) {
	r.Group(func(r chi.Router) {
		if relyingParty != nil {
			r.Use(func(h http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == AuthorizeCallbackPath {
						if code := r.URL.Query().Get("code"); code != "" {
							authorizeCallbackHandler(provider, storage, relyingParty).ServeHTTP(w, r)
							return
						} else if err := r.URL.Query().Get("error"); err != "" {
							authorizeErrorHandler().ServeHTTP(w, r)
							return
						}
					}
					h.ServeHTTP(w, r)
				})
			})
		}

		// Sub router is a gorilla/mux router, we need to override the span name
		// Otherwise it would be "/*" for every path
		r.
			With(func(handler http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// set a fake route pattern in the route pattern to prevent otelchi middleware
					// from overriding the span name
					// The code from otelchi :
					//   // set span name & http route attribute if route pattern cannot be determined
					//	 // during span creation
					//	 if len(routePattern) == 0 {
					//		 routePattern = chi.RouteContext(r.Context()).RoutePattern()
					//		 span.SetAttributes(semconv.HTTPRoute(routePattern))
					//
					//		 spanName = addPrefixToSpanName(tw.requestMethodInSpanName, r.Method, routePattern)
					//		 span.SetName(spanName)
					//	 }
					chi.RouteContext(r.Context()).RoutePatterns = []string{r.URL.Path}
					trace.SpanFromContext(r.Context()).SetName(r.URL.Path)
					handler.ServeHTTP(w, r)
				})
			}).
			Mount("/", provider.HttpHandler())
	})
}
