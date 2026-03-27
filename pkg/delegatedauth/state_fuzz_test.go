package delegatedauth

import (
	"testing"
)

func FuzzDecodeDelegatedState(f *testing.F) {
	// Valid base64-encoded JSON seeds
	valid := DelegatedState{AuthRequestID: "test-123"}
	f.Add(valid.EncodeAsUrlParam())

	empty := DelegatedState{AuthRequestID: ""}
	f.Add(empty.EncodeAsUrlParam())

	// Edge cases: raw strings that are not valid base64/JSON
	f.Add("")
	f.Add("not-base64")
	f.Add("====")
	f.Add("{}")
	f.Add("e30=") // base64 of "{}"
	f.Add("bnVsbA==") // base64 of "null"
	f.Add(string([]byte{0, 1, 2, 3, 4, 5}))
	f.Add("eyJhdXRoUmVxdWVzdElEIjoiIn0=") // base64 of {"authRequestID":""}

	f.Fuzz(func(t *testing.T, input string) {
		result, err := DecodeDelegatedState(input)
		if err != nil {
			return
		}

		// Round-trip: encode then decode should produce the same result
		encoded := result.EncodeAsUrlParam()
		result2, err := DecodeDelegatedState(encoded)
		if err != nil {
			t.Fatalf("round-trip decode failed: %v", err)
		}
		if result.AuthRequestID != result2.AuthRequestID {
			t.Fatalf("round-trip mismatch: %q != %q", result.AuthRequestID, result2.AuthRequestID)
		}
	})
}
