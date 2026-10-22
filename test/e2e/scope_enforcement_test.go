//go:build it

package suite_test

import (
	"fmt"
	"net/http"
	"strings"

	auth "github.com/formancehq/auth/pkg"
	"github.com/formancehq/auth/pkg/testserver"
	"github.com/formancehq/go-libs/v3/logging"
	"github.com/formancehq/go-libs/v3/testing/platform/pgtesting"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/oauth2/clientcredentials"
)

var _ = Context("Auth - Mandatory scope checks", func() {
	db := pgtesting.UsePostgresDatabase(pgServer)

	DescribeTable("enforces management scopes without a configuration flag",
		func(scopes []string, method, path string, expectedStatus int) {
			ctx := logging.TestingContext()
			srv := testserver.New(GinkgoT(), testserver.Configuration{
				PostgresConfiguration: db.GetValue().ConnectionOptions(),
				Output:                GinkgoWriter,
				Debug:                 debug,
				BaseURL:               "http://localhost:8080",
				Clients: []auth.StaticClient{{
					ClientOptions: auth.ClientOptions{
						Id:     "management",
						Name:   "management",
						Scopes: scopes,
					},
					Secrets: []string{"management-secret"},
				}},
			})
			config := clientcredentials.Config{
				ClientID:     "management",
				ClientSecret: "management-secret",
				TokenURL:     fmt.Sprintf("%s/oauth/token", srv.ServerURL()),
			}
			// Fetch the token separately to prove denial comes from the API.
			token, err := config.Token(ctx)
			Expect(err).To(Succeed())
			request, err := http.NewRequestWithContext(ctx, method, srv.ServerURL()+path,
				strings.NewReader(`{"name":"new-client"}`))
			Expect(err).To(Succeed())
			request.Header.Set("Authorization", "Bearer "+token.AccessToken)
			request.Header.Set("Content-Type", "application/json")
			response, err := http.DefaultClient.Do(request)
			Expect(err).To(Succeed())
			defer func() {
				Expect(response.Body.Close()).To(Succeed())
			}()
			Expect(response.StatusCode).To(Equal(expectedStatus))
		},
		Entry("no scopes cannot read clients", []string{}, http.MethodGet, "/clients", http.StatusUnauthorized),
		Entry("no scopes cannot read users", []string{}, http.MethodGet, "/users", http.StatusUnauthorized),
		Entry("no scopes cannot create clients", []string{}, http.MethodPost, "/clients", http.StatusUnauthorized),
		Entry("foreign scopes cannot read clients", []string{"ledger:write"}, http.MethodGet, "/clients", http.StatusUnauthorized),
		Entry("foreign scopes cannot read users", []string{"ledger:write"}, http.MethodGet, "/users", http.StatusUnauthorized),
		Entry("foreign scopes cannot create clients", []string{"ledger:write"}, http.MethodPost, "/clients", http.StatusUnauthorized),
		Entry("auth:read can read clients", []string{"auth:read"}, http.MethodGet, "/clients", http.StatusOK),
		Entry("auth:read can read users", []string{"auth:read"}, http.MethodGet, "/users", http.StatusOK),
		Entry("auth:read cannot create clients", []string{"auth:read"}, http.MethodPost, "/clients", http.StatusUnauthorized),
		Entry("auth:write can read clients", []string{"auth:write"}, http.MethodGet, "/clients", http.StatusOK),
		Entry("auth:write can read users", []string{"auth:write"}, http.MethodGet, "/users", http.StatusOK),
		Entry("auth:write can create clients", []string{"auth:write"}, http.MethodPost, "/clients", http.StatusCreated),
	)
})
