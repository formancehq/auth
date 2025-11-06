package api

import (
	authlib "github.com/formancehq/go-libs/v3/auth"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/uptrace/bun"

	auth "github.com/formancehq/auth/pkg"
)

func addUserRoutes(db *bun.DB, r chi.Router, authenticator authlib.Authenticator) {
	r.With(authlib.Middleware(authenticator)).Route("/users", func(r chi.Router) {
		r.Get("/", listUsers(db))
		r.Route("/{userId}", func(r chi.Router) {
			r.Get("/", readUser(db))
		})
	})
}

func listUsers(db *bun.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users := make([]auth.User, 0)
		if err := db.
			NewSelect().
			Model(&users).
			Scan(r.Context()); err != nil {
			internalServerError(w, r, err)
			return
		}
		writeJSONObject(w, r, users)
	}
}

func readUser(db *bun.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := findById[*auth.User](w, r, db, "userId")
		if user == nil {
			return
		}
		writeJSONObject(w, r, user)
	}
}
