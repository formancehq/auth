//go:build it

package suite_test

import (
	"fmt"
	auth "github.com/formancehq/auth/pkg"
	"github.com/formancehq/auth/pkg/client/models/components"
	"github.com/formancehq/auth/pkg/client/models/operations"
	"github.com/formancehq/auth/pkg/testserver"
	"github.com/formancehq/go-libs/v2/collectionutils"
	"github.com/formancehq/go-libs/v2/logging"
	"github.com/formancehq/go-libs/v2/testing/platform/pgtesting"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"net/http"
)

var _ = Context("Auth - Client credentials", func() {

	var (
		db  = pgtesting.UsePostgresDatabase(pgServer)
		srv *testserver.Server
		ctx = logging.TestingContext()
	)
	BeforeEach(func() {
		srv = testserver.New(GinkgoT(), testserver.Configuration{
			PostgresConfiguration: db.GetValue().ConnectionOptions(),
			DelegatedConfiguration: testserver.DelegatedConfiguration{
				ClientID:     mockOIDC.ClientID,
				ClientSecret: mockOIDC.ClientSecret,
				Issuer:       mockOIDC.Issuer(),
			},
			Output:  GinkgoWriter,
			Debug:   debug,
			BaseURL: "http://localhost:8080",
			Clients: []auth.StaticClient{{
				ClientOptions: auth.ClientOptions{
					Name:    "global",
					Id:      "global",
					Trusted: true,
				},
				Secrets: []string{"global"},
			}},
		})
	})
	Context("with the default static client", func() {
		var (
			httpClient *http.Client
		)
		BeforeEach(func() {
			config := clientcredentials.Config{
				ClientID:     "global",
				ClientSecret: "global",
				TokenURL:     fmt.Sprintf("%s/oauth/token", srv.ServerURL()),
			}
			httpClient = config.Client(ctx)
		})
		When("creating a new brand client", func() {
			var (
				createClientResponse *operations.CreateClientResponse
				createSecretResponse *operations.CreateSecretResponse
				err                  error
			)
			BeforeEach(func() {
				createClientResponse, err = srv.Client(httpClient).Auth.V1.CreateClient(ctx, &components.CreateClientRequest{
					Name:   "client1",
					Scopes: []string{"scope1"},
				})
				Expect(err).To(Succeed())
				Expect(createClientResponse.GetHTTPMeta().Response.StatusCode).To(Equal(http.StatusCreated))

				createSecretResponse, err = srv.Client(httpClient).Auth.V1.CreateSecret(ctx, operations.CreateSecretRequest{
					CreateSecretRequest: &components.CreateSecretRequest{
						Name: "secret1",
					},
					ClientID: createClientResponse.CreateClientResponse.Data.ID,
				})
				Expect(err).To(Succeed())
			})
			When("requiring an access token using client credentials flow", func() {
				var (
					token *oauth2.Token
					err   error
				)
				BeforeEach(func() {
					config := clientcredentials.Config{
						ClientID:     createClientResponse.CreateClientResponse.Data.ID,
						ClientSecret: createSecretResponse.CreateSecretResponse.Data.Clear,
						TokenURL:     fmt.Sprintf("%s/oauth/token", srv.ServerURL()),
						Scopes:       []string{"scope1", "scope2"},
					}
					token, err = config.Token(ctx)
					Expect(err).To(BeNil())
					Expect(token).NotTo(BeNil())
				})
				It("should be ok", func() {
					accessTokenClaims := &oidc.AccessTokenClaims{}
					_, err = oidc.ParseToken(token.AccessToken, accessTokenClaims)
					Expect(err).To(Succeed())

					Expect(accessTokenClaims.Scopes).To(HaveLen(1))
					Expect(collectionutils.Contains(accessTokenClaims.Scopes, "scope1")).To(BeTrue())
				})
			})
		})
	})
})
