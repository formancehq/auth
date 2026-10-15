package api

// Regression for Heal s5-concurrent-secret-create-lost-1. The suite uses real
// PostgreSQL. An external row lock parks all requests before any can write;
// unlocked readers would all read the same old array and lose successful creates.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/formancehq/auth/pkg"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

func TestConcurrentClientSecretMutations(t *testing.T) {
	withDbAndClientRouter(t, func(router chi.Router, db *bun.DB) {
		for _, tc := range []struct {
			name       string
			n          int
			concurrent bool
			mutation   string
		}{{"sequential_2", 2, false, ""}, {"concurrent_2", 2, true, ""}, {"concurrent_5", 5, true, ""}, {"concurrent_8", 8, true, ""}, {"with_secret_delete", 5, true, "delete"}, {"with_client_update", 5, true, "update"}} {
			t.Run(tc.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				client := auth.NewClient(auth.ClientOptions{Name: "concurrent-" + tc.name})
				untouched, untouchedClear := client.GenerateNewSecret(auth.SecretCreate{Name: "untouched"})
				deleted, deletedClear := client.GenerateNewSecret(auth.SecretCreate{Name: "to-delete"})
				_, err := db.NewInsert().Model(client).Exec(ctx)
				require.NoError(t, err)
				responses := make([]*httptest.ResponseRecorder, tc.n)
				create := func(i int) {
					req := httptest.NewRequest(http.MethodPost, "/clients/"+client.Id+"/secrets", strings.NewReader(fmt.Sprintf(`{"name":"secret-%d"}`, i))).WithContext(ctx)
					responses[i] = httptest.NewRecorder()
					router.ServeHTTP(responses[i], req)
				}
				var mutationResponse *httptest.ResponseRecorder
				if tc.concurrent {
					requestCount := tc.n
					if tc.mutation != "" {
						requestCount++
					}
					tx, err := db.BeginTx(ctx, nil)
					require.NoError(t, err)
					defer func() { _ = tx.Rollback() }()
					require.NoError(t, tx.NewSelect().Model(client).Where("id = ?", client.Id).For("UPDATE").Scan(ctx))
					done := make(chan struct{}, requestCount)
					for i := 0; i < tc.n; i++ {
						go func(i int) { create(i); done <- struct{}{} }(i)
					}
					if tc.mutation != "" {
						go func() {
							method, path, body := http.MethodDelete, "/clients/"+client.Id+"/secrets/"+deleted.ID, ""
							if tc.mutation == "update" {
								method, path, body = http.MethodPut, "/clients/"+client.Id, `{"name":"updated"}`
							}
							mutationResponse = httptest.NewRecorder()
							router.ServeHTTP(mutationResponse, httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx))
							done <- struct{}{}
						}()
					}
					// Count locked SELECTs after the fix and locked UPDATEs before it.
					// The database is unique to this test, so no other thread is counted.
					locked := 0
					require.Eventually(t, func() bool {
						err := db.NewRaw(`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query ILIKE '%clients%'`).Scan(ctx, &locked)
						return err == nil && locked == requestCount
					}, 10*time.Second, 10*time.Millisecond, "all writers must be parked on the row lock")
					t.Logf("gate: %d client mutations blocked in PostgreSQL before release", locked)
					require.NoError(t, tx.Commit())
					for i := 0; i < requestCount; i++ {
						select {
						case <-done:
						case <-ctx.Done():
							t.Fatal(ctx.Err())
						}
					}
				} else {
					for i := 0; i < tc.n; i++ {
						create(i)
					}
				}

				if tc.mutation != "" {
					expected := http.StatusNoContent
					if tc.mutation == "update" {
						expected = http.StatusOK
					}
					require.Equal(t, expected, mutationResponse.Code)
				}
				get := httptest.NewRecorder()
				router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/clients/"+client.Id, nil).WithContext(ctx))
				require.Equal(t, http.StatusOK, get.Code)
				view := readTestResponse[clientView](t, get)
				require.NoError(t, db.NewSelect().Model(client).Where("id = ?", client.Id).Scan(ctx))
				require.NoError(t, client.ValidateSecret(untouchedClear), "unrelated existing secret must survive")
				require.Equal(t, untouched.ID, client.Secrets[0].ID)
				expectedCount := tc.n + 2
				if tc.mutation == "delete" {
					expectedCount--
					require.Error(t, client.ValidateSecret(deletedClear), "deleted secret must stay deleted")
				} else {
					require.NoError(t, client.ValidateSecret(deletedClear))
				}
				if tc.mutation == "update" {
					require.Equal(t, "updated", client.Name)
				}
				accepted, refused := 0, 0
				missing := 0
				for _, res := range responses {
					require.Equal(t, http.StatusOK, res.Code)
					result := readTestResponse[secretCreateResult](t, res)
					require.NotEmpty(t, result.Clear)
					found := false
					for _, stored := range view.Secrets {
						if stored.ID == result.ID {
							found = true
						}
					}
					if !found {
						missing++
					}
					// Same Client.ValidateSecret used by OIDC storage; no clear values logged.
					if client.ValidateSecret(result.Clear) == nil {
						accepted++
					} else {
						refused++
					}
				}
				t.Logf("created_HTTP_200=%d listed_GET=%d missing_IDs=%d ValidateSecret_accepted=%d refused=%d", tc.n, len(view.Secrets), missing, accepted, refused)
				require.Equal(t, expectedCount, len(view.Secrets), "every successful creation must remain listed")
				require.Zero(t, missing, "every successful secret ID must remain listed")
				require.Zero(t, refused, "every returned clear must authenticate")
			})
		}
	})
}

func TestCreateSecretCommitFailure(t *testing.T) {
	withDbAndClientRouter(t, func(router chi.Router, db *bun.DB) {
		ctx := context.Background()
		client := auth.NewClient(auth.ClientOptions{})
		_, err := db.NewInsert().Model(client).Exec(ctx)
		require.NoError(t, err)
		// Fail at COMMIT, after UPDATE has succeeded, to test the response boundary.
		_, err = db.ExecContext(ctx, `CREATE FUNCTION reject_client_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test commit failure'; RETURN NEW; END $$`)
		require.NoError(t, err)
		_, err = db.ExecContext(ctx, `CREATE CONSTRAINT TRIGGER reject_client_commit AFTER UPDATE ON clients DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_client_commit()`)
		require.NoError(t, err)

		res := httptest.NewRecorder()
		router.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/clients/"+client.Id+"/secrets", strings.NewReader(`{"name":"not-persisted"}`)))
		require.Equal(t, http.StatusInternalServerError, res.Code)
		require.NotContains(t, res.Body.String(), `"clear"`)
		require.NoError(t, db.NewSelect().Model(client).Where("id = ?", client.Id).Scan(ctx))
		require.Empty(t, client.Secrets)
	})
}

func TestCreateSecretDuringClientDeletion(t *testing.T) {
	withDbAndClientRouter(t, func(router chi.Router, db *bun.DB) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		client := auth.NewClient(auth.ClientOptions{})
		_, err := db.NewInsert().Model(client).Exec(ctx)
		require.NoError(t, err)
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback() }()
		// DELETE takes a conflicting row lock without needing a prior SELECT.
		_, err = tx.NewDelete().Model(client).Where("id = ?", client.Id).Exec(ctx)
		require.NoError(t, err)
		res := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			router.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/clients/"+client.Id+"/secrets", strings.NewReader(`{}`)).WithContext(ctx))
			close(done)
		}()
		require.Eventually(t, func() bool {
			var locked int
			err := db.NewRaw(`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query ILIKE '%clients%'`).Scan(ctx, &locked)
			return err == nil && locked == 1
		}, 10*time.Second, 10*time.Millisecond)
		require.NoError(t, tx.Commit())
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		require.Equal(t, http.StatusNotFound, res.Code)
		require.NotContains(t, res.Body.String(), `"clear"`)
		exists, err := db.NewSelect().Model(client).Where("id = ?", client.Id).Exists(ctx)
		require.NoError(t, err)
		require.False(t, exists)
	})
}
