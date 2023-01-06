/*
Auth API

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: AUTH_VERSION
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package authclient

import (
	"encoding/json"
)

// checks if the ReadUserResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ReadUserResponse{}

// ReadUserResponse struct for ReadUserResponse
type ReadUserResponse struct {
	Data *User `json:"data,omitempty"`
}

// NewReadUserResponse instantiates a new ReadUserResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewReadUserResponse() *ReadUserResponse {
	this := ReadUserResponse{}
	return &this
}

// NewReadUserResponseWithDefaults instantiates a new ReadUserResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewReadUserResponseWithDefaults() *ReadUserResponse {
	this := ReadUserResponse{}
	return &this
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *ReadUserResponse) GetData() User {
	if o == nil || isNil(o.Data) {
		var ret User
		return ret
	}
	return *o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ReadUserResponse) GetDataOk() (*User, bool) {
	if o == nil || isNil(o.Data) {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *ReadUserResponse) HasData() bool {
	if o != nil && !isNil(o.Data) {
		return true
	}

	return false
}

// SetData gets a reference to the given User and assigns it to the Data field.
func (o *ReadUserResponse) SetData(v User) {
	o.Data = &v
}

func (o ReadUserResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ReadUserResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.Data) {
		toSerialize["data"] = o.Data
	}
	return toSerialize, nil
}

type NullableReadUserResponse struct {
	value *ReadUserResponse
	isSet bool
}

func (v NullableReadUserResponse) Get() *ReadUserResponse {
	return v.value
}

func (v *NullableReadUserResponse) Set(val *ReadUserResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableReadUserResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableReadUserResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableReadUserResponse(val *ReadUserResponse) *NullableReadUserResponse {
	return &NullableReadUserResponse{value: val, isSet: true}
}

func (v NullableReadUserResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableReadUserResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
