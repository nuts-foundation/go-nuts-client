package oauth2

import (
	"bytes"
	"context"
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
			tokenEndpoint, _ := url.Parse(httpServer.URL + "/token")
			client := http.Client{
				Transport: &Transport{
					TokenSource:    &noAuthTokenSource{},
					MetadataLoader: &MetadataLoader{},
					Scope:          "test-scope",
					AuthzServerLocators: []AuthorizationServerLocator{
						StaticAuthorizationServerURL(tokenEndpoint),
					},
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
			tokenEndpoint, _ := url.Parse(httpServer.URL + "/token")
			client := http.Client{
				Transport: &Transport{
					TokenSource:    &noAuthTokenSource{},
					MetadataLoader: &MetadataLoader{},
					Scope:          "test-scope",
					AuthzServerLocators: []AuthorizationServerLocator{
						StaticAuthorizationServerURL(tokenEndpoint),
					},
				},
			}

			httpResponse, err := client.Post(httpServer.URL+"/resource", "application/json", bytes.NewReader([]byte("test")))

			require.NoError(t, err)
			require.Equal(t, http.StatusOK, httpResponse.StatusCode)
			require.Equal(t, "test", string(capturedBody))
		})
	})
	t.Run("Resource Server does not require authentication", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		})
		httpServer := httptest.NewServer(mux)
		client := NewClient(nil, "scope")

		httpResponse, err := client.Get(httpServer.URL + "/resource")

		require.NoError(t, err)
		require.Equal(t, http.StatusOK, httpResponse.StatusCode)
		responseBytes, err := io.ReadAll(httpResponse.Body)
		require.NoError(t, err)
		require.Equal(t, "OK", string(responseBytes))
	})
}

func TestTransport_requestToken(t *testing.T) {
	t.Run("scope not set", func(t *testing.T) {
		httpRequest, _ := http.NewRequestWithContext(context.Background(), "GET", "https://resource.example.com", nil)
		transport := &Transport{
			AuthzServerLocators: []AuthorizationServerLocator{
				StaticAuthorizationServerURL(&url.URL{}),
			},
		}

		_, err := transport.requestToken(httpRequest, nil)

		require.EqualError(t, err, "scope is required")
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
