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

// Secret struct for Secret
type Secret struct {
	Name       *string `json:"name,omitempty"`
	Id         string  `json:"id"`
	LastDigits string  `json:"lastDigits"`
	Clear      string  `json:"clear"`
}

// NewSecret instantiates a new Secret object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSecret(id string, lastDigits string, clear string) *Secret {
	this := Secret{}
	this.Id = id
	this.LastDigits = lastDigits
	this.Clear = clear
	return &this
}

// NewSecretWithDefaults instantiates a new Secret object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSecretWithDefaults() *Secret {
	this := Secret{}
	return &this
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *Secret) GetName() string {
	if o == nil || o.Name == nil {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Secret) GetNameOk() (*string, bool) {
	if o == nil || o.Name == nil {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *Secret) HasName() bool {
	if o != nil && o.Name != nil {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *Secret) SetName(v string) {
	o.Name = &v
}

// GetId returns the Id field value
func (o *Secret) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *Secret) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *Secret) SetId(v string) {
	o.Id = v
}

// GetLastDigits returns the LastDigits field value
func (o *Secret) GetLastDigits() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.LastDigits
}

// GetLastDigitsOk returns a tuple with the LastDigits field value
// and a boolean to check if the value has been set.
func (o *Secret) GetLastDigitsOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.LastDigits, true
}

// SetLastDigits sets field value
func (o *Secret) SetLastDigits(v string) {
	o.LastDigits = v
}

// GetClear returns the Clear field value
func (o *Secret) GetClear() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Clear
}

// GetClearOk returns a tuple with the Clear field value
// and a boolean to check if the value has been set.
func (o *Secret) GetClearOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Clear, true
}

// SetClear sets field value
func (o *Secret) SetClear(v string) {
	o.Clear = v
}

func (o Secret) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Name != nil {
		toSerialize["name"] = o.Name
	}
	if true {
		toSerialize["id"] = o.Id
	}
	if true {
		toSerialize["lastDigits"] = o.LastDigits
	}
	if true {
		toSerialize["clear"] = o.Clear
	}
	return json.Marshal(toSerialize)
}

type NullableSecret struct {
	value *Secret
	isSet bool
}

func (v NullableSecret) Get() *Secret {
	return v.value
}

func (v *NullableSecret) Set(val *Secret) {
	v.value = val
	v.isSet = true
}

func (v NullableSecret) IsSet() bool {
	return v.isSet
}

func (v *NullableSecret) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSecret(val *Secret) *NullableSecret {
	return &NullableSecret{value: val, isSet: true}
}

func (v NullableSecret) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSecret) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}