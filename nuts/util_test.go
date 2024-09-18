package nuts

import (
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func Test_ParseResponse(t *testing.T) {
	fn := func(response *http.Response) (*string, error) {
		data, _ := io.ReadAll(response.Body)
		result := string(data)
		return &result, nil
	}
	okResponse := func() *http.Response {
		return &http.Response{
			StatusCode: 200,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader("http-test-response")),
			Request:    httptest.NewRequest(http.MethodGet, "http://example.com", nil),
		}
	}
	nokResponse := func() *http.Response {
		return &http.Response{
			StatusCode: 404,
			Status:     "404 Not Found",
			Body:       io.NopCloser(strings.NewReader("http-test-response")),
			Request:    httptest.NewRequest(http.MethodGet, "http://example.com", nil),
		}
	}
	t.Run("error", func(t *testing.T) {
		_, err := ParseResponse(io.EOF, okResponse(), fn)
		require.EqualError(t, err, "http request failed: EOF")
	})
	t.Run("parse error", func(t *testing.T) {
		_, err := ParseResponse(nil, okResponse(), func(response *http.Response) (*string, error) {
			return nil, io.EOF
		})
		require.EqualError(t, err, "failed to parse response: EOF")
	})
	t.Run("ok", func(t *testing.T) {
		result, err := ParseResponse(nil, okResponse(), fn)
		require.NoError(t, err)
		require.Equal(t, "http-test-response", *result)
	})
	t.Run("non-ok status", func(t *testing.T) {
		_, err := ParseResponse(nil, nokResponse(), fn)
		require.EqualError(t, err, "non-OK status code (status=404 Not Found, url=http://example.com)\nResponse data:\n----------------\nhttp-test-response\n----------------")
	})
}
