package oidc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTerminateSessionRequiresSubject(t *testing.T) {
	// A nil backing storage makes any attempted deletion fail the test.
	facade := &storageFacade{}
	for _, clientID := range []string{"", "machine-client"} {
		require.ErrorContains(t, facade.TerminateSession(t.Context(), "", clientID), "cannot terminate a session without a user subject")
	}
}
