package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	authlib "github.com/formancehq/go-libs/v3/auth"

	"github.com/go-chi/chi/v5"

	"github.com/uptrace/bun"

	auth "github.com/formancehq/auth/pkg"
	_ "github.com/formancehq/go-libs/v3/api"
)

func addClientRoutes(db *bun.DB, r chi.Router, authenticator authlib.Authenticator) {
	r.With(authlib.Middleware(authenticator)).Route("/clients", func(r chi.Router) {
		r.Post("/", createClient(db))
		r.Get("/", listClients(db))
		r.Route("/{clientId}", func(r chi.Router) {
			r.Put("/", updateClient(db))
			r.Delete("/", deleteClient(db))
			r.Get("/", readClient(db))
			r.Route("/secrets", func(r chi.Router) {
				r.Post("/", createSecret(db))
				r.Delete("/{secretId}", deleteSecret(db))
			})
		})
	})
}

type clientSecretView struct {
	ID         string        `json:"id"`
	LastDigits string        `json:"lastDigits"`
	Name       string        `json:"name"`
	Metadata   auth.Metadata `json:"metadata"`
}

type clientView struct {
	auth.ClientOptions
	ID      string                       `json:"id"`
	Secrets auth.Array[clientSecretView] `json:"secrets" bun:"type:text"`
}

func mapBusinessClient(c auth.Client) clientView {
	return clientView{
		ClientOptions: auth.ClientOptions{
			Public:                 c.Public,
			RedirectURIs:           c.RedirectURIs,
			Description:            c.Description,
			Name:                   c.Name,
			PostLogoutRedirectUris: c.PostLogoutRedirectUris,
			Metadata:               c.Metadata,
			Scopes:                 c.Scopes,
			Trusted:                c.Trusted,
		},
		ID: c.Id,
		Secrets: mapList(c.Secrets, func(i auth.ClientSecret) clientSecretView {
			return clientSecretView{
				ID:         i.ID,
				LastDigits: i.LastDigits,
				Name:       i.Name,
				Metadata:   i.Metadata,
			}
		}),
	}
}

type secretCreateResult struct {
	ID         string `json:"id"`
	LastDigits string `json:"lastDigits"`
	Name       string `json:"name"`
	Clear      string `json:"clear"`
}

// mutateClient serializes read-modify-write operations on a client. Every writer
// of the client row must acquire this lock before reading its current secrets.
// A non-nil result means the update AND its transaction have committed.
func mutateClient(w http.ResponseWriter, r *http.Request, db *bun.DB, mutate func(*auth.Client) error) *auth.Client {
	client := &auth.Client{}
	err := db.RunInTx(r.Context(), nil, func(ctx context.Context, tx bun.Tx) error {
		if err := tx.NewSelect().Model(client).
			Where("id = ?", chi.URLParam(r, "clientId")).
			For("UPDATE").Scan(ctx); err != nil {
			return err
		}
		if err := mutate(client); err != nil {
			return err
		}
		_, err := tx.NewUpdate().Model(client).Where("id = ?", client.Id).Exec(ctx)
		return err
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.WriteHeader(http.StatusNotFound)
		} else {
			internalServerError(w, r, err)
		}
		return nil
	}
	return client
}

func deleteSecret(db *bun.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client := mutateClient(w, r, db, func(client *auth.Client) error {
			if !client.DeleteSecret(chi.URLParam(r, "secretId")) {
				return sql.ErrNoRows
			}
			return nil
		})
		if client == nil {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func createSecret(db *bun.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sc := readJSONObject[auth.SecretCreate](w, r)
		if sc == nil {
			return
		}

		var result secretCreateResult
		client := mutateClient(w, r, db, func(client *auth.Client) error {
			secret, clear := client.GenerateNewSecret(*sc)
			result = secretCreateResult{
				ID:         secret.ID,
				LastDigits: secret.LastDigits,
				Name:       secret.Name,
				Clear:      clear,
			}
			return nil
		})
		if client == nil {
			return
		}
		writeJSONObject(w, r, result)
	}
}

func readClient(db *bun.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client := findById[*auth.Client](w, r, db, "clientId")
		if client == nil {
			return
		}
		writeJSONObject(w, r, mapBusinessClient(*client))
	}
}

func deleteClient(db *bun.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := db.
			NewDelete().
			Model(&auth.Client{}).
			Where("id = ?", chi.URLParam(r, "clientId")).
			Exec(r.Context())
		if err != nil {
			internalServerError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func listClients(db *bun.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clients := make([]auth.Client, 0)
		if err := db.
			NewSelect().
			Model(&clients).
			Scan(r.Context()); err != nil {
			internalServerError(w, r, err)
			return
		}
		writeJSONObject(w, r, mapList(clients, mapBusinessClient))
	}
}

func updateClient(db *bun.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		opts := readJSONObject[auth.ClientOptions](w, r)
		if opts == nil {
			return
		}

		client := mutateClient(w, r, db, func(client *auth.Client) error {
			client.Update(*opts)
			return nil
		})
		if client == nil {
			return
		}
		writeJSONObject(w, r, mapBusinessClient(*client))
	}
}

func createClient(db *bun.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		opts := readJSONObject[auth.ClientOptions](w, r)
		if opts == nil {
			return
		}

		c := auth.NewClient(*opts)
		if err := createObject(w, r, db, c); err != nil {
			return
		}

		writeCreatedJSONObject(w, r, mapBusinessClient(*c), c.Id)
	}
}
