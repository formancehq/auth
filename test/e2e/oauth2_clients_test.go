//go:build it

package suite_test

import (
	"fmt"
	"net/http"

	"github.com/formancehq/go-libs/v3/pointer"

	auth "github.com/formancehq/auth/pkg"
	"github.com/formancehq/auth/pkg/client/models/components"
	"github.com/formancehq/auth/pkg/client/models/operations"
	"github.com/formancehq/auth/pkg/testserver"
	"github.com/formancehq/go-libs/v3/logging"
	"github.com/formancehq/go-libs/v3/testing/platform/pgtesting"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/oauth2/clientcredentials"
)

var _ = Context("Auth - OAuth2 Clients Management", func() {

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
					Scopes:  []string{"auth:write"},
				},
				Secrets: []string{"global"},
			}},
			CheckScopes: true,
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
				Scopes:       []string{"auth:write"},
				TokenURL:     fmt.Sprintf("%s/oauth/token", srv.ServerURL()),
			}
			httpClient = config.Client(ctx)
		})

		Describe("Creating clients", func() {
			When("creating a client with minimal information", func() {
				var (
					response *operations.CreateClientResponse
					err      error
				)

				BeforeEach(func() {
					response, err = srv.Client(httpClient).Auth.V1.CreateClient(ctx, &components.CreateClientRequest{
						Name: "test-client",
					})
				})

				It("should succeed", func() {
					Expect(err).To(Succeed())
					Expect(response.GetHTTPMeta().Response.StatusCode).To(Equal(http.StatusCreated))
				})

				It("should return the created client with an ID", func() {
					Expect(response.CreateClientResponse).NotTo(BeNil())
					Expect(response.CreateClientResponse.Data.ID).NotTo(BeEmpty())
					Expect(response.CreateClientResponse.Data.Name).To(Equal("test-client"))
				})
			})

			When("creating a client with all fields", func() {
				var (
					response *operations.CreateClientResponse
					err      error
				)

				BeforeEach(func() {
					public := true
					trusted := false
					response, err = srv.Client(httpClient).Auth.V1.CreateClient(ctx, &components.CreateClientRequest{
						Name:                   "full-client",
						Description:            pointer.For("A full featured client"),
						Public:                 &public,
						Trusted:                &trusted,
						RedirectUris:           []string{"https://example.com/callback"},
						PostLogoutRedirectUris: []string{"https://example.com/logout"},
						Scopes:                 []string{"scope1", "scope2"},
						Metadata: map[string]string{
							"key1": "value1",
							"key2": "42",
						},
					})
				})

				It("should succeed", func() {
					Expect(err).To(Succeed())
					Expect(response.GetHTTPMeta().Response.StatusCode).To(Equal(http.StatusCreated))
				})

				It("should return the client with all fields set", func() {
					client := response.CreateClientResponse.Data
					Expect(client.Name).To(Equal("full-client"))
					Expect(client.Description).NotTo(BeNil())
					Expect(*client.Description).To(Equal("A full featured client"))
					Expect(client.Public).NotTo(BeNil())
					Expect(*client.Public).To(BeTrue())
					Expect(client.Trusted).NotTo(BeNil())
					Expect(*client.Trusted).To(BeFalse())
					Expect(client.RedirectUris).To(ConsistOf("https://example.com/callback"))
					Expect(client.PostLogoutRedirectUris).To(ConsistOf("https://example.com/logout"))
					Expect(client.Scopes).To(ConsistOf("scope1", "scope2"))
					Expect(client.Metadata).To(HaveKeyWithValue("key1", "value1"))
					Expect(client.Metadata).To(HaveKeyWithValue("key2", "42"))
					Expect(client.Secrets).To(BeEmpty())
				})
			})
		})

		Describe("Reading clients", func() {
			var (
				createdClient *operations.CreateClientResponse
			)

			BeforeEach(func() {
				var err error
				createdClient, err = srv.Client(httpClient).Auth.V1.CreateClient(ctx, &components.CreateClientRequest{
					Name:        "readable-client",
					Description: pointer.For("Client for reading tests"),
					Scopes:      []string{"read:scope"},
				})
				Expect(err).To(Succeed())
				Expect(createdClient.GetHTTPMeta().Response.StatusCode).To(Equal(http.StatusCreated))
			})

			When("reading an existing client", func() {
				var (
					response *operations.ReadClientResponse
					err      error
				)

				BeforeEach(func() {
					response, err = srv.Client(httpClient).Auth.V1.ReadClient(ctx, operations.ReadClientRequest{
						ClientID: createdClient.CreateClientResponse.Data.ID,
					})
				})

				It("should succeed", func() {
					Expect(err).To(Succeed())
					Expect(response.GetHTTPMeta().Response.StatusCode).To(Equal(http.StatusOK))
				})

				It("should return the correct client", func() {
					client := response.ReadClientResponse.Data
					Expect(client.ID).To(Equal(createdClient.CreateClientResponse.Data.ID))
					Expect(client.Name).To(Equal("readable-client"))
					Expect(client.Description).NotTo(BeNil())
					Expect(*client.Description).To(Equal("Client for reading tests"))
					Expect(client.Scopes).To(ConsistOf("read:scope"))
				})
			})

			When("reading a non-existent client", func() {
				var (
					err error
				)

				BeforeEach(func() {
					_, err = srv.Client(httpClient).Auth.V1.ReadClient(ctx, operations.ReadClientRequest{
						ClientID: "non-existent-id",
					})
				})

				It("should return an error", func() {
					Expect(err).NotTo(BeNil())
				})
			})
		})

		Describe("Listing clients", func() {
			var (
				client1ID string
				client2ID string
			)

			BeforeEach(func() {
				// Create first client
				response1, err := srv.Client(httpClient).Auth.V1.CreateClient(ctx, &components.CreateClientRequest{
					Name:   "client-1",
					Scopes: []string{"scope1"},
				})
				Expect(err).To(Succeed())
				client1ID = response1.CreateClientResponse.Data.ID

				// Create second client
				response2, err := srv.Client(httpClient).Auth.V1.CreateClient(ctx, &components.CreateClientRequest{
					Name:   "client-2",
					Scopes: []string{"scope2"},
				})
				Expect(err).To(Succeed())
				client2ID = response2.CreateClientResponse.Data.ID
			})

			When("listing all clients", func() {
				var (
					response *operations.ListClientsResponse
					err      error
				)

				BeforeEach(func() {
					response, err = srv.Client(httpClient).Auth.V1.ListClients(ctx)
				})

				It("should succeed", func() {
					Expect(err).To(Succeed())
					Expect(response.GetHTTPMeta().Response.StatusCode).To(Equal(http.StatusOK))
				})

				It("should return all created clients", func() {
					clients := response.ListClientsResponse.Data
					Expect(len(clients)).To(BeNumerically(">=", 2))

					clientIDs := make([]string, 0, len(clients))
					for _, client := range clients {
						clientIDs = append(clientIDs, client.ID)
					}
					Expect(clientIDs).To(ContainElements(client1ID, client2ID))
				})

				It("should include client details", func() {
					clients := response.ListClientsResponse.Data
					var client1 *components.Client
					var client2 *components.Client

					for i := range clients {
						if clients[i].ID == client1ID {
							client1 = &clients[i]
						}
						if clients[i].ID == client2ID {
							client2 = &clients[i]
						}
					}

					Expect(client1).NotTo(BeNil())
					Expect(client1.Name).To(Equal("client-1"))
					Expect(client1.Scopes).To(ConsistOf("scope1"))

					Expect(client2).NotTo(BeNil())
					Expect(client2.Name).To(Equal("client-2"))
					Expect(client2.Scopes).To(ConsistOf("scope2"))
				})
			})
		})

		Describe("Updating clients", func() {
			var (
				createdClient *operations.CreateClientResponse
			)

			BeforeEach(func() {
				var err error
				createdClient, err = srv.Client(httpClient).Auth.V1.CreateClient(ctx, &components.CreateClientRequest{
					Name:        "original-name",
					Description: pointer.For("Original description"),
					Scopes:      []string{"original-scope"},
				})
				Expect(err).To(Succeed())
				Expect(createdClient.GetHTTPMeta().Response.StatusCode).To(Equal(http.StatusCreated))
			})

			When("updating a client with new values", func() {
				var (
					response *operations.UpdateClientResponse
					err      error
				)

				BeforeEach(func() {
					public := true
					trusted := true
					response, err = srv.Client(httpClient).Auth.V1.UpdateClient(ctx, operations.UpdateClientRequest{
						ClientID: createdClient.CreateClientResponse.Data.ID,
						UpdateClientRequest: &components.UpdateClientRequest{
							Name:                   "updated-name",
							Description:            pointer.For("Updated description"),
							Public:                 &public,
							Trusted:                &trusted,
							RedirectUris:           []string{"https://example.com/new-callback"},
							PostLogoutRedirectUris: []string{"https://example.com/new-logout"},
							Scopes:                 []string{"updated-scope1", "updated-scope2"},
							Metadata: map[string]string{
								"updated": "value",
							},
						},
					})
				})

				It("should succeed", func() {
					Expect(err).To(Succeed())
					Expect(response.GetHTTPMeta().Response.StatusCode).To(Equal(http.StatusOK))
				})

				It("should return the updated client", func() {
					client := response.UpdateClientResponse.Data
					Expect(client.ID).To(Equal(createdClient.CreateClientResponse.Data.ID))
					Expect(client.Name).To(Equal("updated-name"))
					Expect(client.Description).NotTo(BeNil())
					Expect(*client.Description).To(Equal("Updated description"))
					Expect(client.Public).NotTo(BeNil())
					Expect(*client.Public).To(BeTrue())
					Expect(client.Trusted).NotTo(BeNil())
					Expect(*client.Trusted).To(BeTrue())
					Expect(client.RedirectUris).To(ConsistOf("https://example.com/new-callback"))
					Expect(client.PostLogoutRedirectUris).To(ConsistOf("https://example.com/new-logout"))
					Expect(client.Scopes).To(ConsistOf("updated-scope1", "updated-scope2"))
					Expect(client.Metadata).To(HaveKeyWithValue("updated", "value"))
				})

				It("should persist the changes", func() {
					readResponse, err := srv.Client(httpClient).Auth.V1.ReadClient(ctx, operations.ReadClientRequest{
						ClientID: createdClient.CreateClientResponse.Data.ID,
					})
					Expect(err).To(Succeed())

					client := readResponse.ReadClientResponse.Data
					Expect(client.Name).To(Equal("updated-name"))
					Expect(client.Description).NotTo(BeNil())
					Expect(*client.Description).To(Equal("Updated description"))
					Expect(client.Scopes).To(ConsistOf("updated-scope1", "updated-scope2"))
				})
			})

			When("updating a non-existent client", func() {
				var err error
				BeforeEach(func() {
					_, err = srv.Client(httpClient).Auth.V1.UpdateClient(ctx, operations.UpdateClientRequest{
						ClientID: "non-existent-id",
						UpdateClientRequest: &components.UpdateClientRequest{
							Name: "updated-name",
						},
					})
				})

				It("should return an error", func() {
					Expect(err).NotTo(BeNil())
				})
			})
		})

		Describe("Deleting clients", func() {
			var (
				createdClient *operations.CreateClientResponse
			)

			BeforeEach(func() {
				var err error
				createdClient, err = srv.Client(httpClient).Auth.V1.CreateClient(ctx, &components.CreateClientRequest{
					Name: "deletable-client",
				})
				Expect(err).To(Succeed())
				Expect(createdClient.GetHTTPMeta().Response.StatusCode).To(Equal(http.StatusCreated))
			})

			When("deleting an existing client", func() {
				var (
					response *operations.DeleteClientResponse
					err      error
				)

				BeforeEach(func() {
					response, err = srv.Client(httpClient).Auth.V1.DeleteClient(ctx, operations.DeleteClientRequest{
						ClientID: createdClient.CreateClientResponse.Data.ID,
					})
				})

				It("should succeed", func() {
					Expect(err).To(Succeed())
					Expect(response.GetHTTPMeta().Response.StatusCode).To(Equal(http.StatusNoContent))
				})

				It("should remove the client from the database", func() {
					_, err := srv.Client(httpClient).Auth.V1.ReadClient(ctx, operations.ReadClientRequest{
						ClientID: createdClient.CreateClientResponse.Data.ID,
					})
					Expect(err).NotTo(BeNil())
				})
			})

			When("deleting a non-existent client", func() {
				var (
					response *operations.DeleteClientResponse
					err      error
				)

				BeforeEach(func() {
					response, err = srv.Client(httpClient).Auth.V1.DeleteClient(ctx, operations.DeleteClientRequest{
						ClientID: "non-existent-id",
					})
				})

				It("should return no error (idempotent)", func() {
					// Delete is typically idempotent, so it might return 204 even if the client doesn't exist
					// The exact behavior depends on the implementation
					Expect(err).To(BeNil())
					Expect(response.GetHTTPMeta().Response.StatusCode).To(BeElementOf(http.StatusNoContent, http.StatusNotFound))
				})
			})
		})

		Describe("Managing client secrets", func() {
			var (
				createdClient *operations.CreateClientResponse
			)

			BeforeEach(func() {
				var err error
				createdClient, err = srv.Client(httpClient).Auth.V1.CreateClient(ctx, &components.CreateClientRequest{
					Name: "client-with-secrets",
				})
				Expect(err).To(Succeed())
				Expect(createdClient.GetHTTPMeta().Response.StatusCode).To(Equal(http.StatusCreated))
			})

			When("creating a secret for a client", func() {
				var (
					createSecretResponse *operations.CreateSecretResponse
					err                  error
				)

				BeforeEach(func() {
					createSecretResponse, err = srv.Client(httpClient).Auth.V1.CreateSecret(ctx, operations.CreateSecretRequest{
						ClientID: createdClient.CreateClientResponse.Data.ID,
						CreateSecretRequest: &components.CreateSecretRequest{
							Name: "secret-1",
							Metadata: map[string]string{
								"purpose": "testing",
							},
						},
					})
				})

				It("should succeed", func() {
					Expect(err).To(Succeed())
				})

				It("should return the secret with clear text", func() {
					secret := createSecretResponse.CreateSecretResponse.Data
					Expect(secret.ID).NotTo(BeEmpty())
					Expect(secret.Name).To(Equal("secret-1"))
					Expect(secret.Clear).NotTo(BeEmpty())
					Expect(secret.LastDigits).NotTo(BeEmpty())
					Expect(len(secret.LastDigits)).To(Equal(4))
				})

				It("should add the secret to the client", func() {
					readResponse, err := srv.Client(httpClient).Auth.V1.ReadClient(ctx, operations.ReadClientRequest{
						ClientID: createdClient.CreateClientResponse.Data.ID,
					})
					Expect(err).To(Succeed())

					client := readResponse.ReadClientResponse.Data
					Expect(client.Secrets).To(HaveLen(1))
					Expect(client.Secrets[0].ID).To(Equal(createSecretResponse.CreateSecretResponse.Data.ID))
					Expect(client.Secrets[0].Name).To(Equal("secret-1"))
					Expect(client.Secrets[0].LastDigits).NotTo(BeEmpty())
				})

				When("creating multiple secrets", func() {
					BeforeEach(func() {
						_, err := srv.Client(httpClient).Auth.V1.CreateSecret(ctx, operations.CreateSecretRequest{
							ClientID: createdClient.CreateClientResponse.Data.ID,
							CreateSecretRequest: &components.CreateSecretRequest{
								Name: "secret-2",
							},
						})
						Expect(err).To(Succeed())
					})

					It("should have both secrets in the client", func() {
						readResponse, err := srv.Client(httpClient).Auth.V1.ReadClient(ctx, operations.ReadClientRequest{
							ClientID: createdClient.CreateClientResponse.Data.ID,
						})
						Expect(err).To(Succeed())

						client := readResponse.ReadClientResponse.Data
						Expect(client.Secrets).To(HaveLen(2))

						secretNames := make([]string, 0, len(client.Secrets))
						for _, secret := range client.Secrets {
							secretNames = append(secretNames, secret.Name)
						}
						Expect(secretNames).To(ContainElements("secret-1", "secret-2"))
					})
				})

				When("deleting a secret", func() {
					var err error
					BeforeEach(func() {
						_, err = srv.Client(httpClient).Auth.V1.DeleteSecret(ctx, operations.DeleteSecretRequest{
							ClientID: createdClient.CreateClientResponse.Data.ID,
							SecretID: createSecretResponse.CreateSecretResponse.Data.ID,
						})
					})

					It("should succeed", func() {
						Expect(err).To(Succeed())
					})

					It("should remove the secret from the client", func() {
						readResponse, err := srv.Client(httpClient).Auth.V1.ReadClient(ctx, operations.ReadClientRequest{
							ClientID: createdClient.CreateClientResponse.Data.ID,
						})
						Expect(err).To(Succeed())

						client := readResponse.ReadClientResponse.Data
						Expect(client.Secrets).To(BeEmpty())
					})
				})

				When("deleting a non-existent secret", func() {
					var err error

					BeforeEach(func() {
						_, err = srv.Client(httpClient).Auth.V1.DeleteSecret(ctx, operations.DeleteSecretRequest{
							ClientID: createdClient.CreateClientResponse.Data.ID,
							SecretID: "non-existent-secret-id",
						})
					})

					It("should return an error", func() {
						Expect(err).NotTo(BeNil())
					})
				})
			})

			When("creating a secret for a non-existent client", func() {
				var err error
				BeforeEach(func() {
					_, err = srv.Client(httpClient).Auth.V1.CreateSecret(ctx, operations.CreateSecretRequest{
						ClientID: "non-existent-id",
						CreateSecretRequest: &components.CreateSecretRequest{
							Name: "secret-name",
						},
					})
				})

				It("should return an error", func() {
					Expect(err).NotTo(BeNil())
				})
			})
		})
	})

	Context("with an unauthorized client", func() {
		var (
			unauthorizedClientID     string
			unauthorizedClientSecret string
			unauthorizedHTTPClient   *http.Client
		)

		BeforeEach(func() {
			// Create a client with the global client (which has auth:write)
			globalConfig := clientcredentials.Config{
				ClientID:     "global",
				ClientSecret: "global",
				Scopes:       []string{"auth:write"},
				TokenURL:     fmt.Sprintf("%s/oauth/token", srv.ServerURL()),
			}
			globalHTTPClient := globalConfig.Client(ctx)

			// Create a new client without auth:write scope
			createResponse, err := srv.Client(globalHTTPClient).Auth.V1.CreateClient(ctx, &components.CreateClientRequest{
				Name:   "unauthorized-client",
				Scopes: []string{"other:scope"},
			})
			Expect(err).To(Succeed())
			Expect(createResponse.GetHTTPMeta().Response.StatusCode).To(Equal(http.StatusCreated))
			unauthorizedClientID = createResponse.CreateClientResponse.Data.ID

			// Create a secret for this client
			createSecretResponse, err := srv.Client(globalHTTPClient).Auth.V1.CreateSecret(ctx, operations.CreateSecretRequest{
				ClientID: unauthorizedClientID,
				CreateSecretRequest: &components.CreateSecretRequest{
					Name: "unauthorized-secret",
				},
			})
			Expect(err).To(Succeed())
			unauthorizedClientSecret = createSecretResponse.CreateSecretResponse.Data.Clear

			// Create HTTP client with unauthorized client credentials
			unauthorizedConfig := clientcredentials.Config{
				ClientID:     unauthorizedClientID,
				ClientSecret: unauthorizedClientSecret,
				Scopes:       []string{},
				TokenURL:     fmt.Sprintf("%s/oauth/token", srv.ServerURL()),
			}
			unauthorizedHTTPClient = unauthorizedConfig.Client(ctx)
		})

		Describe("Accessing clients API without proper authorization", func() {
			When("trying to create a client", func() {
				var (
					err error
				)

				BeforeEach(func() {
					_, err = srv.Client(unauthorizedHTTPClient).Auth.V1.CreateClient(ctx, &components.CreateClientRequest{
						Name: "should-fail",
					})
				})

				It("should be refused", func() {
					Expect(err).NotTo(BeNil())
				})
			})

			When("trying to list clients", func() {
				var (
					err error
				)

				BeforeEach(func() {
					_, err = srv.Client(unauthorizedHTTPClient).Auth.V1.ListClients(ctx)
				})

				It("should be refused", func() {
					Expect(err).NotTo(BeNil())
				})
			})

			When("trying to read a client", func() {
				var (
					err error
				)

				BeforeEach(func() {
					_, err = srv.Client(unauthorizedHTTPClient).Auth.V1.ReadClient(ctx, operations.ReadClientRequest{
						ClientID: unauthorizedClientID,
					})
				})

				It("should be refused", func() {
					Expect(err).NotTo(BeNil())
				})
			})

			When("trying to update a client", func() {
				var (
					err error
				)

				BeforeEach(func() {
					_, err = srv.Client(unauthorizedHTTPClient).Auth.V1.UpdateClient(ctx, operations.UpdateClientRequest{
						ClientID: unauthorizedClientID,
						UpdateClientRequest: &components.UpdateClientRequest{
							Name: "updated-name",
						},
					})
				})

				It("should be refused", func() {
					Expect(err).NotTo(BeNil())
				})
			})

			When("trying to delete a client", func() {
				var (
					err error
				)

				BeforeEach(func() {
					_, err = srv.Client(unauthorizedHTTPClient).Auth.V1.DeleteClient(ctx, operations.DeleteClientRequest{
						ClientID: unauthorizedClientID,
					})
				})

				It("should be refused", func() {
					Expect(err).NotTo(BeNil())
				})
			})

			When("trying to create a secret", func() {
				var (
					err error
				)

				BeforeEach(func() {
					_, err = srv.Client(unauthorizedHTTPClient).Auth.V1.CreateSecret(ctx, operations.CreateSecretRequest{
						ClientID: unauthorizedClientID,
						CreateSecretRequest: &components.CreateSecretRequest{
							Name: "new-secret",
						},
					})
				})

				It("should be refused", func() {
					Expect(err).NotTo(BeNil())
				})
			})

			When("trying to delete a secret", func() {
				var (
					err error
				)

				BeforeEach(func() {
					// First, we need to get the secret ID from the client
					// But we can't read the client, so we'll use a dummy ID
					_, err = srv.Client(unauthorizedHTTPClient).Auth.V1.DeleteSecret(ctx, operations.DeleteSecretRequest{
						ClientID: unauthorizedClientID,
						SecretID: "dummy-secret-id",
					})
				})

				It("should be refused", func() {
					Expect(err).NotTo(BeNil())
				})
			})
		})
	})
})
