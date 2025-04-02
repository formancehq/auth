package testserver

import (
	"context"
	"errors"
	"fmt"
	"github.com/formancehq/auth/cmd"
	auth "github.com/formancehq/auth/pkg"
	"github.com/formancehq/go-libs/v2/bun/bunconnect"
	"gopkg.in/yaml.v3"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	authclient "github.com/formancehq/auth/pkg/client"
	"github.com/formancehq/go-libs/v2/httpserver"
	"github.com/formancehq/go-libs/v2/logging"
	"github.com/formancehq/go-libs/v2/otlp"
	"github.com/formancehq/go-libs/v2/otlp/otlpmetrics"
	"github.com/formancehq/go-libs/v2/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type T interface {
	require.TestingT
	Cleanup(func())
	Helper()
	Logf(format string, args ...any)
}

type OTLPConfig struct {
	BaseConfig otlp.Config
	Metrics    *otlpmetrics.ModuleConfig
}

type DelegatedConfiguration struct {
	ClientID     string
	ClientSecret string
	Issuer       string
}

type ClientConfiguration struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
}

type Configuration struct {
	DelegatedConfiguration DelegatedConfiguration
	PostgresConfiguration  bunconnect.ConnectionOptions
	Output                 io.Writer
	Debug                  bool
	OTLPConfig             *OTLPConfig
	BaseURL                string
	Clients                []auth.StaticClient
}

type Logger interface {
	Logf(fmt string, args ...any)
}

type Server struct {
	configuration Configuration
	logger        Logger
	cancel        func()
	ctx           context.Context
	errorChan     chan error
	id            string
	serverURL     string
}

func (s *Server) Start() error {
	rootCmd := cmd.NewRootCommand()
	args := []string{
		"serve",
		"--" + cmd.ListenFlag, ":0",
		"--" + cmd.BaseUrlFlag, s.configuration.BaseURL,
		"--" + bunconnect.PostgresURIFlag, s.configuration.PostgresConfiguration.DatabaseSourceName,
		"--" + bunconnect.PostgresMaxOpenConnsFlag, fmt.Sprint(s.configuration.PostgresConfiguration.MaxOpenConns),
		"--" + bunconnect.PostgresConnMaxIdleTimeFlag, fmt.Sprint(s.configuration.PostgresConfiguration.ConnMaxIdleTime),
	}
	if s.configuration.PostgresConfiguration.MaxIdleConns != 0 {
		args = append(
			args,
			"--"+bunconnect.PostgresMaxIdleConnsFlag,
			fmt.Sprint(s.configuration.PostgresConfiguration.MaxIdleConns),
		)
	}
	if s.configuration.PostgresConfiguration.MaxOpenConns != 0 {
		args = append(
			args,
			"--"+bunconnect.PostgresMaxOpenConnsFlag,
			fmt.Sprint(s.configuration.PostgresConfiguration.MaxOpenConns),
		)
	}
	if s.configuration.PostgresConfiguration.ConnMaxIdleTime != 0 {
		args = append(
			args,
			"--"+bunconnect.PostgresConnMaxIdleTimeFlag,
			fmt.Sprint(s.configuration.PostgresConfiguration.ConnMaxIdleTime),
		)
	}
	if s.configuration.DelegatedConfiguration.ClientID != "" {
		args = append(args, "--"+cmd.DelegatedClientIDFlag, s.configuration.DelegatedConfiguration.ClientID)
	}
	if s.configuration.DelegatedConfiguration.ClientSecret != "" {
		args = append(args, "--"+cmd.DelegatedClientSecretFlag, s.configuration.DelegatedConfiguration.ClientSecret)
	}
	if s.configuration.DelegatedConfiguration.Issuer != "" {
		args = append(args, "--"+cmd.DelegatedIssuerFlag, s.configuration.DelegatedConfiguration.Issuer)
	}
	if len(s.configuration.Clients) > 0 {
		tmpDir := os.TempDir()
		configFile := filepath.Join(tmpDir, s.id+".yaml")
		f, err := os.OpenFile(configFile, os.O_RDWR|os.O_CREATE, 0666)
		if err != nil {
			return err
		}
		err = yaml.NewEncoder(f).Encode(struct {
			Clients []auth.StaticClient `yaml:"clients"`
		}{
			Clients: s.configuration.Clients,
		})
		if err != nil {
			return err
		}
		args = append(args, "--"+cmd.ConfigFlag, configFile)
	}
	if s.configuration.OTLPConfig != nil {
		if s.configuration.OTLPConfig.Metrics != nil {
			args = append(
				args,
				"--"+otlpmetrics.OtelMetricsExporterFlag, s.configuration.OTLPConfig.Metrics.Exporter,
			)
			if s.configuration.OTLPConfig.Metrics.KeepInMemory {
				args = append(
					args,
					"--"+otlpmetrics.OtelMetricsKeepInMemoryFlag,
				)
			}
			if s.configuration.OTLPConfig.Metrics.OTLPConfig != nil {
				args = append(
					args,
					"--"+otlpmetrics.OtelMetricsExporterOTLPEndpointFlag, s.configuration.OTLPConfig.Metrics.OTLPConfig.Endpoint,
					"--"+otlpmetrics.OtelMetricsExporterOTLPModeFlag, s.configuration.OTLPConfig.Metrics.OTLPConfig.Mode,
				)
				if s.configuration.OTLPConfig.Metrics.OTLPConfig.Insecure {
					args = append(args, "--"+otlpmetrics.OtelMetricsExporterOTLPInsecureFlag)
				}
			}
			if s.configuration.OTLPConfig.Metrics.RuntimeMetrics {
				args = append(args, "--"+otlpmetrics.OtelMetricsRuntimeFlag)
			}
			if s.configuration.OTLPConfig.Metrics.MinimumReadMemStatsInterval != 0 {
				args = append(
					args,
					"--"+otlpmetrics.OtelMetricsRuntimeMinimumReadMemStatsIntervalFlag,
					s.configuration.OTLPConfig.Metrics.MinimumReadMemStatsInterval.String(),
				)
			}
			if s.configuration.OTLPConfig.Metrics.PushInterval != 0 {
				args = append(
					args,
					"--"+otlpmetrics.OtelMetricsExporterPushIntervalFlag,
					s.configuration.OTLPConfig.Metrics.PushInterval.String(),
				)
			}
			if len(s.configuration.OTLPConfig.Metrics.ResourceAttributes) > 0 {
				args = append(
					args,
					"--"+otlp.OtelResourceAttributesFlag,
					strings.Join(s.configuration.OTLPConfig.Metrics.ResourceAttributes, ","),
				)
			}
		}
		if s.configuration.OTLPConfig.BaseConfig.ServiceName != "" {
			args = append(args, "--"+otlp.OtelServiceNameFlag, s.configuration.OTLPConfig.BaseConfig.ServiceName)
		}
	}
	if s.configuration.Debug {
		args = append(args, "--"+service.DebugFlag)
	}

	s.logger.Logf("Starting application with flags: %s", strings.Join(args, " "))
	rootCmd.SetArgs(args)
	rootCmd.SilenceErrors = true
	output := s.configuration.Output
	if output == nil {
		output = io.Discard
	}
	rootCmd.SetOut(output)
	rootCmd.SetErr(output)

	ctx := logging.TestingContext()
	ctx = service.ContextWithLifecycle(ctx)
	ctx = httpserver.ContextWithServerInfo(ctx)
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		s.errorChan <- rootCmd.ExecuteContext(ctx)
	}()

	select {
	case <-service.Ready(ctx):
	case err := <-s.errorChan:
		cancel()
		if err != nil {
			return err
		}

		return errors.New("unexpected service stop")
	}

	s.ctx, s.cancel = ctx, cancel
	s.serverURL = httpserver.URL(s.ctx)

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s.cancel == nil {
		return nil
	}
	s.cancel()
	s.cancel = nil

	// Wait app to be marked as stopped
	select {
	case <-service.Stopped(s.ctx):
	case <-ctx.Done():
		return errors.New("service should have been stopped")
	}

	// Ensure the app has been properly shutdown
	select {
	case err := <-s.errorChan:
		return err
	case <-ctx.Done():
		return errors.New("service should have been stopped without error")
	}
}

func (s *Server) Client(httpClient *http.Client) *authclient.Formance {
	return authclient.New(
		authclient.WithServerURL(s.serverURL),
		authclient.WithClient(httpClient),
	)
}

func (s *Server) ServerURL() string {
	return s.serverURL
}

func (s *Server) Restart(ctx context.Context) error {
	if err := s.Stop(ctx); err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return err
	}

	return nil
}

func (s *Server) Issuer() string {
	return fmt.Sprintf("http://%s", s.serverURL)
}

func New(t T, configuration Configuration) *Server {
	t.Helper()

	srv := &Server{
		logger:        t,
		configuration: configuration,
		id:            uuid.NewString()[:8],
		errorChan:     make(chan error, 1),
	}
	t.Logf("Start testing server")
	require.NoError(t, srv.Start())
	t.Cleanup(func() {
		t.Logf("Stop testing server")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		require.NoError(t, srv.Stop(ctx))
	})

	return srv
}
