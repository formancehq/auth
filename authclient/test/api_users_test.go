/*
Auth API

Testing UsersApiService

*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech);

package authclient

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	openapiclient "github.com/formancehq/auth/authclient"
)

func Test_authclient_UsersApiService(t *testing.T) {

	configuration := openapiclient.NewConfiguration()
	apiClient := openapiclient.NewAPIClient(configuration)

	t.Run("Test UsersApiService ListUsers", func(t *testing.T) {

		t.Skip("skip test")  // remove to run test

		resp, httpRes, err := apiClient.UsersApi.ListUsers(context.Background()).Execute()

		require.Nil(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

	t.Run("Test UsersApiService ReadUser", func(t *testing.T) {

		t.Skip("skip test")  // remove to run test

		var userId interface{}

		resp, httpRes, err := apiClient.UsersApi.ReadUser(context.Background(), userId).Execute()

		require.Nil(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 200, httpRes.StatusCode)

	})

}