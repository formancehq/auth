//go:build it

package suite_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/formancehq/auth/pkg"
	"github.com/formancehq/auth/pkg/testserver"
	"github.com/formancehq/go-libs/v3/logging"
	"github.com/formancehq/go-libs/v3/testing/platform/pgtesting"

	. "github.com/formancehq/go-libs/v3/collectionutils"
	"github.com/golang-jwt/jwt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/oauth2"
)

type claims struct {
	jwt.StandardClaims
	Scopes string `json:"scope"`
}

func forgeSecurityToken(scopes ...string) string {
	claims := claims{
		StandardClaims: jwt.StandardClaims{
			Audience:  "http://localhost:8080",
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
			Issuer:    mockOIDC.Issuer(),
		},
		Scopes: strings.Join(scopes, " "),
	}
	signJWT, err := mockOIDC.Keypair.SignJWT(claims)
	Expect(err).To(BeNil())

	return signJWT
}

func exchangeSecurityToken(ctx context.Context, srv *testserver.Server, securityToken string, scopes ...string) *oauth2.Token {
	scopes = append(scopes, "email")
	form := url.Values{
		"grant_type": []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  []string{securityToken},
		"scope":      []string{strings.Join(scopes, " ")},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.ServerURL()+"/oauth/token",
		bytes.NewBufferString(form.Encode()))
	Expect(err).To(BeNil())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ret, err := http.DefaultClient.Do(req)
	Expect(err).To(BeNil())
	Expect(ret.StatusCode).To(Equal(http.StatusOK))

	stackToken := &oauth2.Token{}
	Expect(json.NewDecoder(ret.Body).Decode(stackToken)).To(Succeed())

	return stackToken
}

var _ = Context("Auth - JWT bearer", func() {

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
	var (
		securityToken string
	)
	BeforeEach(func() {
		securityToken = forgeSecurityToken("openid scope1")
	})
	When("exchanging security token against an access token", func() {
		var (
			token *oauth2.Token
		)
		BeforeEach(func() {
			token = exchangeSecurityToken(ctx, srv, securityToken, "other_scope1 other_scope2")
		})
		It("should be ok, even if wrong scope are asked", func() {
			accessTokenClaims := &oidc.AccessTokenClaims{}
			_, err := oidc.ParseToken(token.AccessToken, accessTokenClaims)
			Expect(err).To(Succeed())

			Expect(accessTokenClaims.Scopes).To(HaveLen(2))
			Expect(Contains(accessTokenClaims.Scopes, "scope1")).To(BeTrue())
			Expect(Contains(accessTokenClaims.Scopes, "openid")).To(BeTrue())
		})
	})
})
