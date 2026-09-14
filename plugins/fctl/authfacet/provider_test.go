package authfacet_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/formancehq/auth/plugins/fctl/authfacet"
	"github.com/formancehq/auth/plugins/fctl/core"
	"github.com/formancehq/fctl-v2-poc/pkg/plugin/sdk"
)

func TestProviderConsumesTheExactHostValidatedSlot(t *testing.T) {
	t.Parallel()
	request := exactRequest([]string{"connectivity:read"})
	host := &recordingHost{
		authorized: sdk.AuthorizeClientCredentialsResponse{CredentialHandle: "opaque-handle", Lease: sdk.LeaseMetadata{ExpiresAtUnix: 123}},
		bound:      sdk.BindCredentialResponse{Binding: "opaque-binding", Lease: sdk.LeaseMetadata{ExpiresAtUnix: 123}},
	}

	binding, err := authfacet.New().Resolve(context.Background(), request, host)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if binding != "opaque-binding" {
		t.Fatalf("Resolve() binding = %q, want opaque-binding", binding)
	}
	if len(host.authorize) != 1 || !reflect.DeepEqual(host.authorize[0], (sdk.AuthorizeClientCredentialsRequest{
		Slot:   *request.CredentialSlot,
		Intent: sdk.ClientCredentialsIntent{Service: sdk.ServiceConnectivity, Scopes: []string{"connectivity:read"}},
	})) {
		t.Fatalf("AuthorizeClientCredentials() requests = %#v", host.authorize)
	}
	if len(host.bind) != 1 || !reflect.DeepEqual(host.bind[0], (sdk.BindCredentialRequest{
		Slot: *request.CredentialSlot, CredentialHandle: "opaque-handle", Operations: []string{"connectivity.configs.list"},
	})) {
		t.Fatalf("BindCredential() requests = %#v", host.bind)
	}
}

func TestProviderPreservesPresentEmptyExactScopes(t *testing.T) {
	t.Parallel()
	request := exactRequest([]string{})
	host := &recordingHost{
		authorized: sdk.AuthorizeClientCredentialsResponse{CredentialHandle: "opaque-handle"},
		bound:      sdk.BindCredentialResponse{Binding: "opaque-binding"},
	}

	if _, err := authfacet.New().Resolve(context.Background(), request, host); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if host.authorize[0].Intent.Scopes == nil || len(host.authorize[0].Intent.Scopes) != 0 {
		t.Fatalf("AuthorizeClientCredentials() scopes = %#v, want present empty exact set", host.authorize[0].Intent.Scopes)
	}
}

func TestProviderRejectsOIDCAndNonFinalFlowsBeforeBrokerAccess(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*sdk.AuthRequest)
	}{
		{name: "OIDC without final slot", mutate: func(request *sdk.AuthRequest) { request.CredentialSlot = nil }},
		{name: "wrong capability", mutate: func(request *sdk.AuthRequest) { request.Capability = "auth.membership" }},
		{name: "multiple operations", mutate: func(request *sdk.AuthRequest) {
			request.Operations = append(request.Operations, "connectivity.configs.get")
		}},
		{name: "slot mismatch", mutate: func(request *sdk.AuthRequest) { request.CredentialSlot.Service = sdk.ServiceLedger }},
		{name: "different provider", mutate: func(request *sdk.AuthRequest) { request.CredentialSlot.Provider = "other" }},
		{name: "absent scope set", mutate: func(request *sdk.AuthRequest) { request.CredentialSlot.Scopes = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := exactRequest([]string{"connectivity:read"})
			test.mutate(&request)
			host := &recordingHost{}
			_, err := authfacet.New().Resolve(context.Background(), request, host)
			var failure sdk.Failure
			if !errors.As(err, &failure) || failure.Code != string(sdk.FailureOperationNotPermitted) {
				t.Fatalf("Resolve() error = %#v, want operation_not_permitted", err)
			}
			if len(host.authorize) != 0 || len(host.bind) != 0 {
				t.Fatalf("broker was called: authorize=%#v bind=%#v", host.authorize, host.bind)
			}
		})
	}
}

func TestProviderFailsClosedWhenDirectionalBrokerIsUnavailable(t *testing.T) {
	t.Parallel()
	_, err := authfacet.New().Resolve(context.Background(), exactRequest([]string{"connectivity:read"}), baseHost{})
	var failure sdk.Failure
	if !errors.As(err, &failure) || failure.Code != string(sdk.FailureOperationNotPermitted) {
		t.Fatalf("Resolve() error = %#v, want operation_not_permitted", err)
	}
}

func TestProviderRejectsEmptyDirectionalBrokerValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		host *recordingHost
	}{
		{
			name: "empty credential handle",
			host: &recordingHost{
				authorized: sdk.AuthorizeClientCredentialsResponse{},
				bound:      sdk.BindCredentialResponse{Binding: "must-not-bind"},
			},
		},
		{
			name: "empty credential binding",
			host: &recordingHost{
				authorized: sdk.AuthorizeClientCredentialsResponse{CredentialHandle: "opaque-handle"},
				bound:      sdk.BindCredentialResponse{},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			binding, err := authfacet.New().Resolve(context.Background(), exactRequest([]string{"connectivity:read"}), test.host)
			var failure sdk.Failure
			if binding != "" || !errors.As(err, &failure) || failure.Code != string(sdk.FailureOperationNotPermitted) {
				t.Fatalf("Resolve() = (%q, %#v), want empty/operation_not_permitted", binding, err)
			}
			if test.name == "empty credential handle" && len(test.host.bind) != 0 {
				t.Fatalf("BindCredential() requests = %#v, want none", test.host.bind)
			}
		})
	}
}

func TestProviderPropagatesDirectionalBrokerFailureWithoutFallback(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		host      *recordingHost
		wantError error
		wantBinds int
	}{
		{
			name:      "authorization cancellation",
			host:      &recordingHost{authorizeErr: context.Canceled},
			wantError: context.Canceled,
		},
		{
			name: "binding failure",
			host: &recordingHost{
				authorized: sdk.AuthorizeClientCredentialsResponse{CredentialHandle: "opaque-handle"},
				bindErr:    errBrokerRejected,
			},
			wantError: errBrokerRejected,
			wantBinds: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			binding, err := authfacet.New().Resolve(context.Background(), exactRequest([]string{"connectivity:read"}), test.host)
			if binding != "" || !errors.Is(err, test.wantError) {
				t.Fatalf("Resolve() = (%q, %v), want empty/%v", binding, err, test.wantError)
			}
			if len(test.host.authorize) != 1 || len(test.host.bind) != test.wantBinds {
				t.Fatalf("broker calls authorize=%d bind=%d, want 1/%d", len(test.host.authorize), len(test.host.bind), test.wantBinds)
			}
		})
	}
}

func TestProviderAdvertisesOnlyAuthStack(t *testing.T) {
	t.Parallel()
	provider := authfacet.New()
	if got, want := provider.Metadata(), (sdk.AuthProviderMetadata{Name: core.Name, Version: core.Version}); got != want {
		t.Fatalf("Metadata() = %#v, want %#v", got, want)
	}
	if got, want := provider.Provides(), []string{"auth.stack"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Provides() = %#v, want %#v", got, want)
	}
	var _ sdk.AuthProvider = provider
}

func exactRequest(scopes []string) sdk.AuthRequest {
	slot := sdk.CredentialSlot{
		Profile: "profile", Service: sdk.ServiceConnectivity, Capability: "auth.stack",
		Provider: core.Name, ProviderVersion: core.Version, ArtifactDigest: "sha256:fixture",
		FacetProtocolVersion: sdk.CurrentAuthProviderFacetProtocolVersion, ProfileCapabilityGeneration: 7,
		OrganizationID: "org", StackID: "stack", Audience: "connectivity", Scopes: scopes,
	}
	return sdk.AuthRequest{
		Capability: "auth.stack", Service: sdk.ServiceConnectivity,
		Target:     sdk.TargetCoordinates{OrganizationID: "org", StackID: "stack"},
		Operations: []string{"connectivity.configs.list"}, CredentialSlot: &slot,
	}
}

type baseHost struct{}

func (baseHost) Load(context.Context, sdk.CredentialSlot) (sdk.CredentialHandle, sdk.LeaseMetadata, sdk.StoreState, error) {
	return "", sdk.LeaseMetadata{}, "", errors.New("unexpected Load")
}
func (baseHost) AuthorizeOIDC(context.Context, sdk.CredentialSlot, sdk.OIDCIntent) (sdk.CredentialHandle, sdk.LeaseMetadata, error) {
	return "", sdk.LeaseMetadata{}, errors.New("unexpected AuthorizeOIDC")
}
func (baseHost) Refresh(context.Context, sdk.CredentialSlot, sdk.CredentialHandle, sdk.RefreshIntent) (sdk.CredentialHandle, sdk.LeaseMetadata, error) {
	return "", sdk.LeaseMetadata{}, errors.New("unexpected Refresh")
}
func (baseHost) Exchange(context.Context, sdk.CredentialSlot, sdk.CredentialHandle, sdk.ExchangeIntent) (sdk.CredentialHandle, sdk.LeaseMetadata, error) {
	return "", sdk.LeaseMetadata{}, errors.New("unexpected Exchange")
}
func (baseHost) Invalidate(context.Context, sdk.CredentialSelector) error {
	return errors.New("unexpected Invalidate")
}
func (baseHost) Bind(context.Context, sdk.CredentialHandle, sdk.BindingSpec) (sdk.ServiceBinding, error) {
	return "", errors.New("unexpected Bind")
}

type recordingHost struct {
	baseHost
	authorize    []sdk.AuthorizeClientCredentialsRequest
	bind         []sdk.BindCredentialRequest
	authorized   sdk.AuthorizeClientCredentialsResponse
	bound        sdk.BindCredentialResponse
	authorizeErr error
	bindErr      error
}

var errBrokerRejected = errors.New("broker rejected")

func (h *recordingHost) AuthorizeClientCredentials(_ context.Context, request sdk.AuthorizeClientCredentialsRequest) (sdk.AuthorizeClientCredentialsResponse, error) {
	h.authorize = append(h.authorize, request)
	return h.authorized, h.authorizeErr
}
func (h *recordingHost) BindCredential(_ context.Context, request sdk.BindCredentialRequest) (sdk.BindCredentialResponse, error) {
	h.bind = append(h.bind, request)
	return h.bound, h.bindErr
}
