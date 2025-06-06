// Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT.

package components

type CreateClientRequest struct {
	Public                 *bool          `json:"public,omitempty"`
	RedirectUris           []string       `json:"redirectUris,omitempty"`
	Description            *string        `json:"description,omitempty"`
	Name                   string         `json:"name"`
	Trusted                *bool          `json:"trusted,omitempty"`
	PostLogoutRedirectUris []string       `json:"postLogoutRedirectUris,omitempty"`
	Metadata               map[string]any `json:"metadata,omitempty"`
	Scopes                 []string       `json:"scopes,omitempty"`
}

func (o *CreateClientRequest) GetPublic() *bool {
	if o == nil {
		return nil
	}
	return o.Public
}

func (o *CreateClientRequest) GetRedirectUris() []string {
	if o == nil {
		return nil
	}
	return o.RedirectUris
}

func (o *CreateClientRequest) GetDescription() *string {
	if o == nil {
		return nil
	}
	return o.Description
}

func (o *CreateClientRequest) GetName() string {
	if o == nil {
		return ""
	}
	return o.Name
}

func (o *CreateClientRequest) GetTrusted() *bool {
	if o == nil {
		return nil
	}
	return o.Trusted
}

func (o *CreateClientRequest) GetPostLogoutRedirectUris() []string {
	if o == nil {
		return nil
	}
	return o.PostLogoutRedirectUris
}

func (o *CreateClientRequest) GetMetadata() map[string]any {
	if o == nil {
		return nil
	}
	return o.Metadata
}

func (o *CreateClientRequest) GetScopes() []string {
	if o == nil {
		return nil
	}
	return o.Scopes
}
