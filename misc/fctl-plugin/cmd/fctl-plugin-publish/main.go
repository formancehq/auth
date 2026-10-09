// fctl-plugin-publish uploads GoReleaser binaries and emits catalogue schema 1.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/formancehq/auth/misc/fctl-plugin/internal/catalogue"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		log.New(os.Stderr, "", 0).Print(err)
		os.Exit(1)
	}
}

func run(args []string, output, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("fctl-plugin-publish", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var options catalogue.PublishOptions
	flags.StringVar(&options.ServiceVersion, "service-version", "", "Exact Auth service version (release tag without v)")
	flags.StringVar(&options.ManifestPath, "manifest", "", "SDK manifest exported by the native plugin")
	flags.StringVar(&options.ArtifactsPath, "artifacts", "", "GoReleaser artifacts.json")
	flags.StringVar(&options.SourceRoot, "source-root", "", "Root containing raw GoReleaser binaries")
	flags.StringVar(&options.Registry, "registry", "https://ghcr.io", "OCI registry HTTPS origin")
	flags.StringVar(&options.Repository, "repository", "formancehq/fctl-plugin-auth", "OCI repository")
	flags.StringVar(&options.Layout, "layout", "", "Write a local OCI image layout instead of pushing to the registry")
	flags.IntVar(&options.Revision, "revision", 1, "Positive plugin revision for the exact Auth version")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}

	return catalogue.Publish(context.Background(), options, output, diagnostics)
}
