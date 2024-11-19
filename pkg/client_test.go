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
		expectedErr          bool
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
			expectedErr: false,
		},
		{
			staticClients: []auth.StaticClient{
				{
					Secrets: []string{"$ERROR"},
				},
			},
			environmentVariables: map[string]string{},
			expectedErr:          true,
		},
	}

	for _, tc := range testCases {
		t.Run("TestStaticClientFromEnvironment", func(t *testing.T) {
			for key, value := range tc.environmentVariables {
				os.Setenv(key, value)
			}

			for _, staticClient := range tc.staticClients {
				loadedClient, err := staticClient.FromEnvironment()

				switch {
				case tc.expectedErr && err == nil:
					t.Errorf("Expected error, got nil")
					fallthrough
				case !tc.expectedErr && err != nil:
					t.Errorf("Expected nil, got error: %v", err)
					fallthrough
				default:
					if tc.expectedErr {
						return
					}

					for _, secret := range loadedClient.Secrets {
						require.NotContains(t, secret, "$")
						require.NotEmpty(t, secret)
					}
				}

			}
		})
	}
}
