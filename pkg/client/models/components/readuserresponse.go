// Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT.

package components

type ReadUserResponse struct {
	Data *User `json:"data,omitempty"`
}

func (o *ReadUserResponse) GetData() *User {
	if o == nil {
		return nil
	}
	return o.Data
}
