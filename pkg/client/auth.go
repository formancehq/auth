// Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT.

package client

type Auth struct {
	V1 *V1

	sdkConfiguration sdkConfiguration
}

func newAuth(sdkConfig sdkConfiguration) *Auth {
	return &Auth{
		sdkConfiguration: sdkConfig,
		V1:               newV1(sdkConfig),
	}
}
