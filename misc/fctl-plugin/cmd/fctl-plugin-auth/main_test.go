package main

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/formancehq/fctl/pkg/pluginsdk"
)

func TestManifestFlag(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := run([]string{"--manifest"}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	var manifest pluginsdk.Manifest
	if err := json.Unmarshal(output.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Name != "auth" || manifest.Version != serviceVersion || manifest.ProtocolVersion != pluginsdk.ProtocolVersion {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	if _, err := pluginsdk.FindCommand(manifest, []string{"auth", "clients", "create"}); err != nil {
		t.Fatal(err)
	}
}

func TestVersionFlag(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := run([]string{"--version"}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	var version versionMetadata
	if err := json.Unmarshal(output.Bytes(), &version); err != nil {
		t.Fatal(err)
	}
	if version.Name != "auth" || version.ServiceVersion != serviceVersion || version.Revision != 1 || version.ProtocolVersion != pluginsdk.ProtocolVersion {
		t.Fatalf("unexpected version metadata: %#v", version)
	}
}

func TestInvalidMetadataArguments(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"--manifest", "--version"}, {"--manifest", "extra"}, {"--unknown"}} {
		if err := run(args, io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted invalid arguments: %v", args)
		}
	}
	if err := run([]string{"--help"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidBuildMetadata(t *testing.T) {
	oldVersion, oldRevision := serviceVersion, revision
	t.Cleanup(func() { serviceVersion, revision = oldVersion, oldRevision })
	for _, value := range []string{"", "0", "-1", "invalid"} {
		revision = value
		var output bytes.Buffer
		if err := run([]string{"--version"}, &output, io.Discard); err == nil || output.Len() != 0 {
			t.Fatalf("accepted revision %q: output=%s err=%v", value, output.String(), err)
		}
	}
	revision = "1"
	serviceVersion = ""
	var output bytes.Buffer
	if err := run([]string{"--manifest"}, &output, io.Discard); err == nil || output.Len() != 0 {
		t.Fatalf("accepted empty service version: output=%s err=%v", output.String(), err)
	}
}
