package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/formancehq/fctl/pkg/pluginsdk"
	"github.com/formancehq/fctl/pkg/pluginsdk/transport"
)

type authenticatedTransport struct{ base http.RoundTripper }

func (t authenticatedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer synthetic-host-token")
	return t.base.RoundTrip(r)
}

func TestStandaloneExecutableUsesHostHTTPBroker(t *testing.T) {
	t.Parallel()
	binary := buildFixtureBinary(t)
	checkFixtureMetadata(t, binary)
	const payload = `{"name":"automation","public":false,"metadata":{"purpose":"fixture"}}`
	const result = `{ "data": { "id": "c1", "name": "automation", "extra": 9007199254740993 } }`
	var calls atomic.Int32
	server := httptest.NewServer(fixtureHandler(t, &calls, payload, result))
	defer server.Close()
	client := &http.Client{Transport: authenticatedTransport{base: http.DefaultTransport}}
	p, err := transport.Open(t.Context(), binary, client, server.URL+"/api/auth")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	}()
	m, err := p.GetManifest(t.Context())
	if err != nil || m.Version != "2.5.0-beta.1" || m.Root.Target != "stack" {
		t.Fatalf("transport manifest=%+v, err=%v", m, err)
	}
	command, err := pluginsdk.FindCommand(m, []string{"auth", "clients", "create"})
	if err != nil || len(command.Inputs) != 8 {
		t.Fatalf("transport form=%+v, err=%v", command.Inputs, err)
	}
	req := pluginsdk.ExecuteRequest{CommandPath: []string{"auth", "clients", "create"}, Body: json.RawMessage(payload), Endpoint: server.URL + "/api/auth"}
	response, err := p.Execute(t.Context(), req)
	if err != nil || string(response.Data) != result || calls.Load() != 1 {
		t.Fatalf("standalone calls=%d result=%s, err=%v", calls.Load(), response.Data, err)
	}
	req.Body = json.RawMessage(`{"name":""}`)
	response, err = p.Execute(t.Context(), req)
	if err == nil || len(response.Data) != 0 || calls.Load() != 1 {
		t.Fatalf("invalid payload reached broker: calls=%d, err=%v", calls.Load(), err)
	}
}

func buildFixtureBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "fctl-plugin-auth")
	// All arguments are fixed by this test; only the owned output directory varies.
	//nolint:gosec // G204: this builds trusted product code into a test-owned temporary directory.
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary,
		"-ldflags", "-X main.serviceVersion=2.5.0-beta.1 -X main.revision=2", ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build standalone executable: %s, %v", output, err)
	}
	return binary
}

func checkFixtureMetadata(t *testing.T, binary string) {
	t.Helper()
	manifest := fixtureMetadata(t, binary, "--manifest")
	var m pluginsdk.Manifest
	if err := json.Unmarshal(manifest, &m); err != nil || m.Version != "2.5.0-beta.1" || m.Name != "auth" || m.Service != "auth" || m.ProtocolVersion != pluginsdk.ProtocolVersion {
		t.Fatalf("binary manifest=%s, err=%v", manifest, err)
	}
	checkFixtureVersion(t, fixtureMetadata(t, binary, "--version"))
}

func checkFixtureVersion(t *testing.T, output []byte) {
	t.Helper()
	var m versionMetadata
	if err := json.Unmarshal(output, &m); err != nil || m.ServiceVersion != "2.5.0-beta.1" || m.Revision != 2 || m.Name != "auth" || m.ProtocolVersion != pluginsdk.ProtocolVersion {
		t.Fatalf("binary version=%s, err=%v", output, err)
	}
}

func fixtureMetadata(t *testing.T, binary, flag string) []byte {
	t.Helper()
	//nolint:gosec // G204: the executable was built by this test and flags are fixed metadata options.
	output, err := exec.CommandContext(t.Context(), binary, flag).Output()
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func fixtureHandler(t *testing.T, calls *atomic.Int32, payload, result string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		if req.Header.Get("Authorization") != "Bearer synthetic-host-token" {
			t.Error("host authentication was not applied")
		}
		if req.Method != http.MethodPost || req.URL.Path != "/api/auth/clients" || req.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request: %s %s", req.Method, req.URL)
		}
		checkFixturePayload(t, req, payload)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if _, err := io.WriteString(w, result); err != nil {
			t.Error(err)
		}
	})
}

func checkFixturePayload(t *testing.T, req *http.Request, payload string) {
	t.Helper()
	body, err := io.ReadAll(req.Body)
	var got, want map[string]any
	decodeErr := json.Unmarshal(body, &got)
	wantErr := json.Unmarshal([]byte(payload), &want)
	if err != nil || decodeErr != nil || wantErr != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("request changed: %s, read=%v decode=%v expected=%v", body, err, decodeErr, wantErr)
	}
}
