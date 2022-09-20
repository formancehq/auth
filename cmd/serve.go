package cmd

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	auth "github.com/formancehq/auth/pkg"
	"github.com/formancehq/auth/pkg/api"
	"github.com/formancehq/auth/pkg/delegatedauth"
	"github.com/formancehq/auth/pkg/storage"
	"github.com/numary/go-libs/sharedlogging"
	"github.com/numary/go-libs/sharedotlp/pkg/sharedotlptraces"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/fx"
)

const (
	postgresUriFlag           = "postgres-uri"
	delegatedClientIDFlag     = "delegated-client-id"
	delegatedClientSecretFlag = "delegated-client-secret"
	delegatedIssuerFlag       = "delegated-issuer"
	baseUrlFlag               = "base-url"
	signingKeyFlag            = "signing-key"
	configNameFlag            = "config-name"
	configTypeFlag            = "config-type"
	configPathFlag            = "config-path"
)

var serveCmd = &cobra.Command{
	Use: "serve",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return bindFlagsToViper(cmd)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		baseUrl := viper.GetString(baseUrlFlag)
		if baseUrl == "" {
			return errors.New("base url must be defined")
		}

		delegatedClientID := viper.GetString(delegatedClientIDFlag)
		if delegatedClientID == "" {
			return errors.New("delegated client id must be defined")
		}

		delegatedClientSecret := viper.GetString(delegatedClientSecretFlag)
		if delegatedClientSecret == "" {
			return errors.New("delegated client secret must be defined")
		}

		delegatedIssuer := viper.GetString(delegatedIssuerFlag)
		if delegatedIssuer == "" {
			return errors.New("delegated issuer must be defined")
		}

		signingKey := viper.GetString(signingKeyFlag)
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

		viper.SetConfigName(viper.GetString(configNameFlag))
		viper.SetConfigType(viper.GetString(configTypeFlag))
		viper.AddConfigPath(viper.GetString(configPathFlag))
		if err := viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				// Config file not found; ignore error if desired
				sharedlogging.GetLogger(cmd.Context()).Infof("no viper config file found")
			} else {
				// Config file was found but another error was produced
				panic(errors.Wrap(err, "reading viper config file"))
			}
		}

		type staticClients struct {
			Clients []auth.ClientOptions `json:"clients" yaml:"clients"`
		}
		scs := staticClients{}
		if err := viper.Unmarshal(&scs); err != nil {
			panic(errors.Wrap(err, "unmarshal viper config"))
		}
		spew.Dump("STATIC CLIENTS FROM CONFIG", scs)

		options := []fx.Option{
			fx.Supply(fx.Annotate(cmd.Context(), fx.As(new(context.Context)))),
			api.Module(baseUrl, ":8080"),
			storage.Module(viper.GetString(postgresUriFlag), key),
			delegatedauth.Module(delegatedauth.Config{
				Issuer:       delegatedIssuer,
				ClientID:     delegatedClientID,
				ClientSecret: delegatedClientSecret,
				RedirectURL:  fmt.Sprintf("%s/delegatedoidc/callback", baseUrl),
			}),
			fx.Invoke(func() {
				sharedlogging.Infof("App started.")
			}),
			fx.NopLogger,
		}

		if tm := sharedotlptraces.CLITracesModule(viper.GetViper()); tm != nil {
			options = append(options, tm)
		}

		app := fx.New(options...)
		err = app.Start(cmd.Context())
		if err != nil {
			return err
		}
		<-app.Done()

		return app.Err()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().String(postgresUriFlag, "", "Postgres uri")
	serveCmd.Flags().String(delegatedIssuerFlag, "", "Delegated OIDC issuer")
	serveCmd.Flags().String(delegatedClientIDFlag, "", "Delegated OIDC client id")
	serveCmd.Flags().String(delegatedClientSecretFlag, "", "Delegated OIDC client secret")
	serveCmd.Flags().String(baseUrlFlag, "http://localhost:8080", "Base service url")
	serveCmd.Flags().String(signingKeyFlag, "", "Signing key")

	serveCmd.Flags().String(configNameFlag, "viper-config", "Config file name without extension")
	serveCmd.Flags().String(configTypeFlag, "yaml", "Config file type. REQUIRED if the config file does not have the extension in the name")
	serveCmd.Flags().String(configPathFlag, ".", "Path to look for the config file in")

	sharedotlptraces.InitOTLPTracesFlags(serveCmd.Flags())
}
