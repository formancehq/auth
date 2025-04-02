// Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT.

package operations

import (
	"github.com/formancehq/auth/pkg/client/models/components"
)

type ListUsersResponse struct {
	HTTPMeta components.HTTPMetadata `json:"-"`
	// List of users
	ListUsersResponse *components.ListUsersResponse
}

func (o *ListUsersResponse) GetHTTPMeta() components.HTTPMetadata {
	if o == nil {
		return components.HTTPMetadata{}
	}
	return o.HTTPMeta
}

func (o *ListUsersResponse) GetListUsersResponse() *components.ListUsersResponse {
	if o == nil {
		return nil
	}
	return o.ListUsersResponse
}
