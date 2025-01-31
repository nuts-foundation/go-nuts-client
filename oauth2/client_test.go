package oauth2

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestClient_RoundTrip(t *testing.T) {
	t.Run("Resource Server requires authentication", func(t *testing.T) {
		t.Run("GET request", func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /resource", func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer token" {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte("Unauthorized"))
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("Access granted"))
			})
			httpServer := httptest.NewServer(mux)
			client := http.Client{
				Transport: &Transport{
					TokenSource: &noAuthTokenSource{},
					Scope:       "test-scope",
				},
			}

			httpResponse, err := client.Get(httpServer.URL + "/resource")

			require.NoError(t, err)
			require.Equal(t, http.StatusOK, httpResponse.StatusCode)
		})
		t.Run("POST request (request body is buffered to be sent multiple times)", func(t *testing.T) {
			mux := http.NewServeMux()
			var capturedBody []byte
			mux.HandleFunc("POST /resource", func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer token" {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte("Unauthorized"))
					return
				}
				var err error
				capturedBody, err = io.ReadAll(r.Body)
				require.NoError(t, err)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("Access granted"))
			})
			httpServer := httptest.NewServer(mux)
			client := http.Client{
				Transport: &Transport{
					TokenSource: &noAuthTokenSource{},
					Scope:       "test-scope",
				},
			}

			httpResponse, err := client.Post(httpServer.URL+"/resource", "application/json", bytes.NewReader([]byte("test")))

			require.NoError(t, err)
			require.Equal(t, http.StatusOK, httpResponse.StatusCode)
			require.Equal(t, "test", string(capturedBody))
		})
	})
}

var _ TokenSource = &noAuthTokenSource{}

type noAuthTokenSource struct {
}

func (n noAuthTokenSource) Token(httpRequest *http.Request, authzServerURL *url.URL, scope string) (*Token, error) {
	return &Token{
		AccessToken: "token",
		TokenType:   "Bearer",
	}, nil
}
