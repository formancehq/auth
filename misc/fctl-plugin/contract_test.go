package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/formancehq/fctl/pkg/pluginsdk"

	auth "github.com/formancehq/auth/misc/fctl-plugin"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPublicVersionContract(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"2.5.0", "2.5.0-beta.1+build.42", "dev", ""} {
		t.Run(version, func(t *testing.T) {
			t.Parallel()
			p := auth.NewVersion(nil, version)
			m, err := p.GetManifest(t.Context())
			if version == "" {
				version = "dev"
			}
			if err != nil {
				t.Fatal(err)
			}
			checkPublicManifest(t, m, version)
			m.Root.Subcommands[0].Use = "mutated"
			fresh, err := p.GetManifest(t.Context())
			if err != nil || fresh.Root.Subcommands[0].Use != "info" || fresh.Version != version {
				t.Fatalf("instance manifest changed: %+v, %v", fresh, err)
			}
		})
	}
	m, err := auth.New(nil).GetManifest(t.Context())
	if err != nil || m.Version != "dev" {
		t.Fatalf("default manifest=%+v, err=%v", m, err)
	}
}

func checkPublicManifest(t *testing.T, m pluginsdk.Manifest, version string) {
	t.Helper()
	if m.Name != "auth" || m.Service != "auth" || m.Version != version || m.ProtocolVersion != pluginsdk.ProtocolVersion || m.Root.Use != "auth" || m.Root.Target != "stack" {
		t.Fatalf("manifest=%+v", m)
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var decoded pluginsdk.Manifest
	if err := json.Unmarshal(data, &decoded); err != nil || !reflect.DeepEqual(m, decoded) {
		t.Fatalf("metadata round trip: %v", err)
	}
}

func TestPublicValidationBeforeNetwork(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		args []string
		body string
	}{
		{"clients update", []string{"c1"}, `{"name":""}`},
		{"clients update", []string{"c1"}, `{"name":"  "}`},
		{"clients update", []string{"c1"}, `{"name":null}`},
		{"clients update", []string{"c1"}, `{"metadata":{"number":9007199254740993}}`},
		{"clients update", []string{"c1"}, `{"unknown":true}`},
		{"clients update", []string{"c1"}, `[]`},
		{"clients update", []string{"c1"}, `{"name":"valid"} {}`},
		{"clients create", nil, `{"name":""}`},
		{"clients secrets create", []string{"c1"}, `{"name":" "}`},
		{"clients show", []string{".."}, ""},
		{"clients secrets delete", []string{"c1", "."}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.path+tc.body, func(t *testing.T) {
			p := auth.New(&http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
				t.Fatal("invalid request reached network")
				return nil, nil
			})})
			req := pluginsdk.ExecuteRequest{CommandPath: strings.Fields("auth " + tc.path), Args: tc.args, Body: json.RawMessage(tc.body), Endpoint: "https://example.test/auth"}
			if tc.body == "" {
				req.Body = nil
			}
			if tc.path == "clients update" || tc.path == "clients secrets delete" {
				req.Flags = map[string]string{"confirm": "true"}
			}
			res, err := p.Execute(t.Context(), req)
			if err == nil || len(res.Data) != 0 {
				t.Fatalf("data=%s err=%v", res.Data, err)
			}
		})
	}
}

func TestPublicExecutionCancellation(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"info", "clients create", "clients delete", "clients update"} {
		t.Run(path, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			p := auth.New(&http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
				t.Fatal("canceled request reached network")
				return nil, nil
			})})
			res, err := p.Execute(ctx, pluginsdk.ExecuteRequest{CommandPath: strings.Fields("auth " + path)})
			if !errors.Is(err, context.Canceled) || len(res.Data) != 0 {
				t.Fatalf("data=%s err=%v", res.Data, err)
			}
		})
	}
}

func TestPublicInFlightCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{})
	p := auth.New(&http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})})
	done := make(chan error, 1)
	go func() {
		_, err := p.Execute(ctx, pluginsdk.ExecuteRequest{CommandPath: []string{"auth", "info"}, Endpoint: "https://example.test/auth"})
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}

func TestPublicUpdateCancellationPreventsWrite(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var calls atomic.Int32
	p := auth.New(&http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) != 1 || r.Method != http.MethodGet {
			t.Fatal("write after cancellation")
		}
		cancel()
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"data":{"id":"c1","name":"original"}}`))}, nil
	})})
	res, err := p.Execute(ctx, pluginsdk.ExecuteRequest{
		CommandPath: []string{"auth", "clients", "update"}, Args: []string{"c1"}, Flags: map[string]string{"confirm": "true"},
		Body: json.RawMessage(`{"description":"new"}`), Endpoint: "https://example.test/auth",
	})
	if !errors.Is(err, context.Canceled) || len(res.Data) != 0 || calls.Load() != 1 {
		t.Fatalf("calls=%d data=%s err=%v", calls.Load(), res.Data, err)
	}
}
