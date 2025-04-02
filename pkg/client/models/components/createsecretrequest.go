// Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT.

package components

type CreateSecretRequest struct {
	Name     string         `json:"name"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

func (o *CreateSecretRequest) GetName() string {
	if o == nil {
		return ""
	}
	return o.Name
}

func (o *CreateSecretRequest) GetMetadata() map[string]any {
	if o == nil {
		return nil
	}
	return o.Metadata
}
