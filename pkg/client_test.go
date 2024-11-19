package auth_test

import (
	"os"
	"testing"

	auth "github.com/formancehq/auth/pkg"
	"github.com/stretchr/testify/require"
)

func TestStaticClientFromEnvironment(t *testing.T) {
	type testCase struct {
		staticClients        []auth.StaticClient
		environmentVariables map[string]string
		expectedErr          error
	}

	testCases := []testCase{
		{
			staticClients: []auth.StaticClient{
				{
					Secrets: []string{"$SECRET"},
				},
			},
			environmentVariables: map[string]string{
				"SECRET": "secret",
			},
			expectedErr: nil,
		},
		{
			staticClients: []auth.StaticClient{
				{
					Secrets: []string{"$ERROR"},
				},
			},
			environmentVariables: map[string]string{},
			expectedErr:          auth.ErrEnvironmentVariableNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run("TestStaticClientFromEnvironment", func(t *testing.T) {
			for key, value := range tc.environmentVariables {
				os.Setenv(key, value)
			}

			for _, staticClient := range tc.staticClients {
				loadedClient, err := staticClient.FromEnvironment()
				if tc.expectedErr != nil {
					require.Error(t, err)
					require.ErrorIs(t, err, tc.expectedErr)
					return
				}
				for _, secret := range loadedClient.Secrets {
					require.NotContains(t, secret, "$")
					require.NotEmpty(t, secret)
				}
			}
		})
	}
}
