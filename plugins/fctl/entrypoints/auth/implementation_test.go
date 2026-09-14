//go:build fctl_component_guest

package export_formance_fctl_plugin_lifecycle

import (
	"bytes"
	"testing"

	pb "github.com/formancehq/fctl-v2-poc/pkg/plugin/protocol/componentbridgev1alpha1"
	"github.com/formancehq/fctl-v2-poc/pkg/plugin/sdk"
	"google.golang.org/protobuf/proto"
)

func TestDescribeExportsAuthCommandsAndProvider(t *testing.T) {
	descriptor, err := pb.DecodeDescriptorEnvelope(Describe())
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.Metadata.Name != "auth" || len(descriptor.Commands) != 9 || len(descriptor.AuthProviders) != 1 || descriptor.AuthProviders[0].Capabilities[0] != "auth.stack" {
		t.Fatalf("descriptor = %#v", descriptor)
	}
	for _, command := range descriptor.Commands {
		if command.ID != "auth.v1.clients.secrets.create" {
			continue
		}
		if len(command.SensitiveOutputs) != 1 || command.SensitiveOutputs[0].JSONPointer != "/data/clear" || len(command.SensitiveOutputs[0].AllowedDeliveries) != 2 || command.SensitiveOutputs[0].AllowedDeliveries[0] != sdk.SensitiveDisplayOnce || command.SensitiveOutputs[0].AllowedDeliveries[1] != sdk.SensitiveProfileAuth {
			t.Fatalf("guest createSecret sensitive outputs = %#v", command.SensitiveOutputs)
		}
		return
	}
	t.Fatal("guest descriptor omits createSecret")
}

func TestGuestCreateSecretLifecycleRequestsResumesWithoutLeakingAndCloses(t *testing.T) {
	const (
		executionID = "auth-create-secret"
		clearSecret = "must-not-emit"
	)
	start := authCreateSecretStart(t, executionID)

	frames := Start(executionID, start)
	if len(frames) != 1 {
		t.Fatalf("Start frames = %d, want one host request", len(frames))
	}
	requestEnvelope := decodeAuthEnvelope(t, frames[0], pb.MessageKind_MESSAGE_KIND_HOST_REQUEST)
	var request pb.HostRequestPayload
	decodeAuthPayload(t, requestEnvelope, &request)
	product := request.GetProduct()
	if product.GetService() != pb.Service_SERVICE_AUTH || product.GetCapability() != "auth.stack" || product.GetOperationId() != "createSecret" {
		t.Fatalf("product request = %#v", product)
	}
	if httpRequest := product.GetHttp(); httpRequest.GetMethod() != "POST" || httpRequest.GetPath() != "/clients/c1/secrets" || string(httpRequest.GetBody()) != `{"name":"main"}` {
		t.Fatalf("HTTP request = %#v", httpRequest)
	}

	frames = Resume(executionID, authEnvelope(t, executionID, pb.MessageKind_MESSAGE_KIND_HOST_RESPONSE, &pb.HostResponsePayload{
		CorrelationId: request.GetCorrelationId(),
		Response: &pb.HostResponsePayload_Product{Product: &pb.ProductResponse{
			Status: 200, ContentType: "application/json",
			Body: []byte(`{"data":{"id":"s1","name":"main","lastDigits":"1234","clear":"` + clearSecret + `"}}`),
		}},
	}))
	if len(frames) != 2 {
		t.Fatalf("Resume frames = %d, want result and termination", len(frames))
	}
	for _, frame := range frames {
		if bytes.Contains(frame, []byte(clearSecret)) {
			t.Fatal("guest frame leaked clear secret material")
		}
	}
	eventEnvelope := decodeAuthEnvelope(t, frames[0], pb.MessageKind_MESSAGE_KIND_EVENT)
	var event pb.EventPayload
	decodeAuthPayload(t, eventEnvelope, &event)
	result := event.GetCommand().GetResult()
	if result.GetOperationId() != "auth.v1.clients.secrets.create" || string(result.GetData()) != `{"name":"main","id":"s1","lastDigits":"1234"}` {
		t.Fatalf("public result = %#v", result)
	}
	terminalEnvelope := decodeAuthEnvelope(t, frames[1], pb.MessageKind_MESSAGE_KIND_TERMINATION)
	var terminal pb.TerminationPayload
	decodeAuthPayload(t, terminalEnvelope, &terminal)
	if !terminal.GetSuccess() {
		t.Fatalf("termination = %#v", &terminal)
	}
	Close(executionID)

	const cancelID = "auth-create-secret-cancel"
	if frames := Start(cancelID, authCreateSecretStart(t, cancelID)); len(frames) != 1 {
		t.Fatalf("cancel Start frames = %d, want one host request", len(frames))
	}
	frames = Cancel(cancelID)
	if len(frames) != 1 {
		t.Fatalf("Cancel frames = %d, want one termination", len(frames))
	}
	cancelEnvelope := decodeAuthEnvelope(t, frames[0], pb.MessageKind_MESSAGE_KIND_TERMINATION)
	var canceled pb.TerminationPayload
	decodeAuthPayload(t, cancelEnvelope, &canceled)
	if got := canceled.GetFailure().GetCode(); got != string(sdk.FailureCanceled) {
		t.Fatalf("cancel failure = %q, want %q", got, sdk.FailureCanceled)
	}
	Close(cancelID)
	if frames := Start(cancelID, authCreateSecretStart(t, cancelID)); len(frames) != 1 {
		t.Fatalf("Start after Close frames = %d, want fresh host request", len(frames))
	}
	Cancel(cancelID)
	Close(cancelID)
}

// The guest boundary must refuse an attested Auth major 1 before it emits any
// host request, so a host on a superseded service line cannot reach product
// traffic through the component.
func TestGuestRejectsASupersededAuthMajorOneStart(t *testing.T) {
	const executionID = "auth-create-secret-major-one"
	frames := Start(executionID, authCreateSecretStartWithVersion(t, executionID, "1.0.0", 1))
	if len(frames) != 1 {
		t.Fatalf("Start frames = %d, want one termination", len(frames))
	}
	envelope := decodeAuthEnvelope(t, frames[0], pb.MessageKind_MESSAGE_KIND_TERMINATION)
	var terminal pb.TerminationPayload
	decodeAuthPayload(t, envelope, &terminal)
	if terminal.GetSuccess() {
		t.Fatal("guest admitted an incompatible Auth major 1 service context")
	}
	if got := terminal.GetFailure().GetCode(); got != string(sdk.FailureInvalidArgument) {
		t.Fatalf("failure code = %q, want %q", got, sdk.FailureInvalidArgument)
	}
	Close(executionID)
}

func authCreateSecretStart(t *testing.T, executionID string) []byte {
	t.Helper()
	return authCreateSecretStartWithVersion(t, executionID, "2.5.0", 2)
}

func authCreateSecretStartWithVersion(t *testing.T, executionID, version string, major uint32) []byte {
	t.Helper()
	return authEnvelope(t, executionID, pb.MessageKind_MESSAGE_KIND_START_EXECUTION, &pb.StartPayload{
		Start: &pb.StartPayload_Command{Command: &pb.CommandStart{
			CommandId:       "auth.v1.clients.secrets.create",
			Arguments:       []string{"c1", "main"},
			Target:          &pb.TargetCoordinates{OrganizationId: "org", StackId: "stack"},
			ServiceVersions: []*pb.ServiceVersion{{Service: pb.Service_SERVICE_AUTH, Version: version, Major: major}},
			Continuation:    &pb.ContinuationControl{Mode: pb.ContinuationMode_CONTINUATION_MODE_SINGLE_PAGE},
		}},
	})
}

func authEnvelope(t *testing.T, executionID string, kind pb.MessageKind, payload proto.Message) []byte {
	t.Helper()
	encodedPayload := authMarshal(t, payload)
	return authMarshal(t, &pb.PluginEnvelope{
		ProtocolMajor: pb.ProtocolMajor,
		FacetKind:     pb.FacetKind_FACET_KIND_COMMAND_PROVIDER,
		MessageKind:   kind,
		ExecutionId:   executionID,
		Payload:       encodedPayload,
	})
}

func decodeAuthEnvelope(t *testing.T, encoded []byte, kind pb.MessageKind) *pb.PluginEnvelope {
	t.Helper()
	var envelope pb.PluginEnvelope
	if err := proto.Unmarshal(encoded, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if envelope.GetProtocolMajor() != pb.ProtocolMajor || envelope.GetFacetKind() != pb.FacetKind_FACET_KIND_COMMAND_PROVIDER || envelope.GetMessageKind() != kind {
		t.Fatalf("envelope = %#v, want command %s", &envelope, kind)
	}
	return &envelope
}

func decodeAuthPayload(t *testing.T, envelope *pb.PluginEnvelope, payload proto.Message) {
	t.Helper()
	if err := proto.Unmarshal(envelope.GetPayload(), payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
}

func authMarshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
