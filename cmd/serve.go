package cmd

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	authlib "github.com/formancehq/go-libs/v3/auth"
	oidclib "github.com/formancehq/go-libs/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/formancehq/go-libs/v3/aws/iam"
	"github.com/formancehq/go-libs/v3/bun/bunconnect"
	"github.com/formancehq/go-libs/v3/collectionutils"
	"github.com/formancehq/go-libs/v3/licence"
	"github.com/formancehq/go-libs/v3/logging"

	"github.com/formancehq/go-libs/v3/otlp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	auth "github.com/formancehq/auth/pkg"
	"github.com/formancehq/auth/pkg/api"
	"github.com/formancehq/auth/pkg/delegatedauth"
	"github.com/formancehq/auth/pkg/oidc"
	"github.com/formancehq/auth/pkg/storage/sqlstorage"
	sharedapi "github.com/formancehq/go-libs/v3/api"
	"github.com/formancehq/go-libs/v3/otlp/otlpmetrics"
	"github.com/formancehq/go-libs/v3/otlp/otlptraces"
	"github.com/formancehq/go-libs/v3/service"
	"github.com/formancehq/go-libs/v5/pkg/audit"
	"github.com/formancehq/go-libs/v5/pkg/fx/messagingfx"
	"github.com/formancehq/go-libs/v5/pkg/messaging/publish"
	logging5 "github.com/formancehq/go-libs/v5/pkg/observe/log"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	zLogging "github.com/zitadel/logging"
	"go.uber.org/fx"
)

const (
	ServiceName = "auth"

	DelegatedClientIDFlag     = "delegated-client-id"
	DelegatedClientSecretFlag = "delegated-client-secret"
	DelegatedIssuerFlag       = "delegated-issuer"
	BaseUrlFlag               = "base-url"
	AuthIssuersFlag           = "auth-issuers"
	ListenFlag                = "listen"
	SigningKeyFlag            = "signing-key"
	ConfigFlag                = "config"

	compromisedSigningKeySHA256 = "679e01c92ee655f2d88fa3612f120e897ba219fcb84cec36045e581e85b323f8"
)

func rejectCompromisedSigningKey(key any) error {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(der)
	if hex.EncodeToString(digest[:]) == compromisedSigningKeySHA256 {
		return errors.New("signing key is compromised and must be rotated")
	}
	return nil
}

func otlpHttpClientModule(debug bool) fx.Option {
	return fx.Decorate(func() *http.Client {
		return otlpHttpClient(debug)
	})
}

func otlpHttpClient(debug bool) *http.Client {
	return &http.Client{
		Transport: otlp.NewRoundTripper(http.DefaultTransport, debug, otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
			str := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
			if len(r.URL.Query()) == 0 {
				return str
			}

			return fmt.Sprintf("%s?%s", str, r.URL.Query().Encode())
		})),
	}
}

func newServeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "serve",
		RunE: runServe,
	}

	cmd.Flags().String(DelegatedIssuerFlag, "", "Delegated OIDC issuer")
	cmd.Flags().String(DelegatedClientIDFlag, "", "Delegated OIDC client id")
	cmd.Flags().String(DelegatedClientSecretFlag, "", "Delegated OIDC client secret")
	cmd.Flags().String(BaseUrlFlag, "http://localhost:8080", "Base service url")
	cmd.Flags().StringSlice(AuthIssuersFlag, []string{}, "Additional trusted issuer URLs for multi-domain support")
	cmd.Flags().String(SigningKeyFlag, "", "PEM-encoded PKCS#1 RSA private key used to sign tokens (required)")
	cmd.Flags().String(ListenFlag, ":8080", "Listening address")
	cmd.Flags().String(ConfigFlag, "", "Config file name without extension")

	audit.AddFlags(cmd.Flags())
	publish.AddFlags("auth", cmd.Flags())
	service.AddFlags(cmd.Flags())
	licence.AddFlags(cmd.Flags())
	otlp.AddFlags(cmd.Flags())
	otlptraces.AddFlags(cmd.Flags())
	otlpmetrics.AddFlags(cmd.Flags())
	bunconnect.AddFlags(cmd.Flags())
	iam.AddFlags(cmd.Flags())

	return cmd
}

func runServe(cmd *cobra.Command, _ []string) error {
	baseUrl, _ := cmd.Flags().GetString(BaseUrlFlag)
	if baseUrl == "" {
		return errors.New("base url must be defined")
	}

	additionalIssuers, _ := cmd.Flags().GetStringSlice(AuthIssuersFlag)
	trustedIssuers := append([]string{baseUrl}, additionalIssuers...)

	signingKey, _ := cmd.Flags().GetString(SigningKeyFlag)
	if signingKey == "" {
		return errors.New("signing key must be defined")
	}

	block, _ := pem.Decode([]byte(signingKey))
	if block == nil {
		return errors.New("invalid signing key, cannot parse as PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	if err := rejectCompromisedSigningKey(&key.PublicKey); err != nil {
		return err
	}

	type configuration struct {
		Clients []auth.StaticClient `json:"clients" yaml:"clients"`
	}
	o := configuration{}

	config, _ := cmd.Flags().GetString(ConfigFlag)
	if config != "" {
		configFile, err := os.Open(config)
		if err != nil {
			return err
		}
		if err := yaml.NewDecoder(configFile).Decode(&o); err != nil {
			return err
		}
	}

	o.Clients = collectionutils.Map(o.Clients, func(client auth.StaticClient) auth.StaticClient {
		c, err := client.FromEnvironment()
		if err != nil {
			logging.FromContext(cmd.Context()).Errorf("error while loading secrets from environment: %v", err)
		}
		return c
	})

	zLogging.SetOutput(cmd.OutOrStdout())

	connectionOptions, err := bunconnect.ConnectionOptionsFromFlags(cmd)
	if err != nil {
		return err
	}

	listen, _ := cmd.Flags().GetString(ListenFlag)

	auditConfig, err := audit.ConfigFromFlags(cmd.Flags())
	if err != nil {
		return err
	}

	options := []fx.Option{
		otlpHttpClientModule(service.IsDebug(cmd)),
		fx.Provide(func() logging5.Logger {
			return logging5.NewDefaultLogger(cmd.OutOrStdout(), service.IsDebug(cmd), false, false)
		}),
		messagingfx.PublishModuleFromFlags(cmd, service.IsDebug(cmd)),
		fx.Supply(fx.Annotate(cmd.Context(), fx.As(new(context.Context)))),
		sqlstorage.Module(*connectionOptions, key, service.IsDebug(cmd), o.Clients...),
		oidc.Module(key, baseUrl, trustedIssuers, o.Clients...),
		api.Module(
			listen,
			baseUrl,
			trustedIssuers,
			sharedapi.ServiceInfo{
				Version: Version,
				Debug:   service.IsDebug(cmd),
			},
			service.IsDebug(cmd),
			auditConfig,
		),
		authlib.Module(authlib.ModuleConfig{
			Enabled:     true,
			Issuers:     trustedIssuers,
			CheckScopes: true,
			Service:     ServiceName,
		}),
		fx.Decorate(func() authlib.Authenticator {
			staticKeySet := oidclib.NewStaticKeySet(jose.JSONWebKey{
				Key:       &key.PublicKey,
				KeyID:     oidc.SigningKeyID(key),
				Algorithm: string(jose.RS256),
				Use:       oidclib.KeyUseSignature,
			})
			keySets := make(map[string]oidclib.KeySet, len(trustedIssuers))
			for _, issuer := range trustedIssuers {
				keySets[issuer] = staticKeySet
			}
			return authlib.NewJWTAuth(keySets, ServiceName, true)
		}),
	}

	delegatedIssuer, _ := cmd.Flags().GetString(DelegatedIssuerFlag)
	if delegatedIssuer != "" {
		delegatedClientID, _ := cmd.Flags().GetString(DelegatedClientIDFlag)
		if delegatedClientID == "" {
			return errors.New("delegated client id must be defined")
		}

		delegatedClientSecret, _ := cmd.Flags().GetString(DelegatedClientSecretFlag)
		if delegatedClientSecret == "" {
			return errors.New("delegated client secret must be defined")
		}

		options = append(options,
			fx.Supply(delegatedauth.Config{
				Issuer:       delegatedIssuer,
				ClientID:     delegatedClientID,
				ClientSecret: delegatedClientSecret,
				RedirectURL:  fmt.Sprintf("%s/authorize/callback", baseUrl),
			}),
			delegatedauth.Module(),
		)
	}

	options = append(options,
		otlp.FXModuleFromFlags(cmd, otlp.WithServiceVersion(Version)),
		otlptraces.FXModuleFromFlags(cmd),
		otlpmetrics.FXModuleFromFlags(cmd),
		licence.FXModuleFromFlags(cmd, ServiceName),
	)

	return service.New(cmd.OutOrStdout(), options...).Run(cmd)
}
