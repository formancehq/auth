package test_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	httpClient = http.DefaultClient

	serverBaseURL string
)

func TestMain(m *testing.M) {
	serverBaseURL = "http://localhost:8888"

	os.Exit(m.Run())
}

func requestServer(t *testing.T, method, url string, expectedCode int, body ...any) io.ReadCloser {
	return request(t, method, serverBaseURL+url, body, expectedCode)
}

func request(t *testing.T, method, url string, body []any, expectedCode int) io.ReadCloser {
	var err error
	var req *http.Request
	if len(body) > 0 {
		req, err = http.NewRequestWithContext(context.Background(), method, url, buffer(t, body[0]))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequestWithContext(context.Background(), method, url, nil)
	}
	require.NoError(t, err)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, expectedCode, resp.StatusCode)
	return resp.Body
}

func buffer(t *testing.T, v any) *bytes.Buffer {
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewBuffer(data)
}
