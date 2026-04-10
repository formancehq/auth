package delegatedauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

type DelegatedState struct {
	AuthRequestID string `json:"authRequestID"`
}

func (s DelegatedState) EncodeAsUrlParam() string {
	buf := bytes.NewBufferString("")
	encoder := base64.NewEncoder(base64.URLEncoding, buf)
	if err := json.NewEncoder(encoder).Encode(s); err != nil {
		panic(err)
	}
	if err := encoder.Close(); err != nil {
		panic(err)
	}
	return buf.String()
}

func DecodeDelegatedState(v string) (*DelegatedState, error) {
	ret := &DelegatedState{}
	if err := json.NewDecoder(base64.NewDecoder(base64.URLEncoding, bytes.NewBufferString(v))).Decode(ret); err != nil {
		return nil, err
	}
	return ret, nil
}
