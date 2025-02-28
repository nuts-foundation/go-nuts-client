package oauth2

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func TestClient_RoundTrip(t *testing.T) {
	t.Run("Resource Server requires authentication", func(t *testing.T) {
		t.Run("GET request", func(t *testing.T) {
			mux := http.NewServeMux()
			invocations := 0
			mux.HandleFunc("GET /resource", func(w http.ResponseWriter, r *http.Request) {
				invocations++
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
			require.Equal(t, 1, invocations)
		})
		t.Run("401 Unauthorized retries HTTP request with fresh token", func(t *testing.T) {
			t.Run("GET request", func(t *testing.T) {
				mux := http.NewServeMux()
				var capturedBody []byte
				invocations := 0
				mux.HandleFunc("GET /resource", func(w http.ResponseWriter, r *http.Request) {
					invocations++
					// Reject the first token
					if r.Header.Get("Authorization") != "Bearer token2" {
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
						TokenSource: &incrementingAuthTokenSource{},
						Scope:       "test-scope",
					},
				}

				httpResponse, err := client.Get(httpServer.URL + "/resource")

				require.NoError(t, err)
				require.Equal(t, http.StatusOK, httpResponse.StatusCode)
				require.Empty(t, string(capturedBody))
				require.Equal(t, 2, invocations)
			})
			t.Run("max. number of retries reached", func(t *testing.T) {
				mux := http.NewServeMux()
				mux.HandleFunc("GET /resource", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte("Unauthorized"))
				})
				httpServer := httptest.NewServer(mux)
				tokenSource := &incrementingAuthTokenSource{}
				client := http.Client{
					Transport: &Transport{
						TokenSource: tokenSource,
						Scope:       "test-scope",
					},
				}

				httpResponse, err := client.Get(httpServer.URL + "/resource")

				require.NoError(t, err)
				require.Equal(t, http.StatusUnauthorized, httpResponse.StatusCode)
				require.Equal(t, 2, tokenSource.count)
			})
			t.Run("POST request (request body is buffered to be sent multiple times)", func(t *testing.T) {
				mux := http.NewServeMux()
				var capturedBody []byte
				mux.HandleFunc("POST /resource", func(w http.ResponseWriter, r *http.Request) {
					// Reject the first token
					if r.Header.Get("Authorization") != "Bearer token2" {
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
						TokenSource: &incrementingAuthTokenSource{},
						Scope:       "test-scope",
					},
				}

				httpResponse, err := client.Post(httpServer.URL+"/resource", "application/json", bytes.NewReader([]byte("test")))

				require.NoError(t, err)
				require.Equal(t, http.StatusOK, httpResponse.StatusCode)
				require.Equal(t, "test", string(capturedBody))
			})
			t.Run("POST request with form values", func(t *testing.T) {
				mux := http.NewServeMux()
				var capturedBody []byte
				mux.HandleFunc("POST /resource", func(w http.ResponseWriter, r *http.Request) {
					// Reject the first token
					if r.Header.Get("Authorization") != "Bearer token2" {
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
						TokenSource: &incrementingAuthTokenSource{},
						Scope:       "test-scope",
					},
				}

				httpResponse, err := client.PostForm(httpServer.URL+"/resource", url.Values{"key": {"value"}})

				require.NoError(t, err)
				require.Equal(t, http.StatusOK, httpResponse.StatusCode)
				require.Equal(t, "key=value", string(capturedBody))
			})
		})
	})
	t.Run("unreachable server", func(t *testing.T) {
		httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		}))
		httpServer.Close()

		tokenSource := &incrementingAuthTokenSource{}
		client := http.Client{
			Transport: &Transport{
				TokenSource: tokenSource,
				Scope:       "test-scope",
			},
		}

		httpResponse, err := client.Get(httpServer.URL + "/resource")

		require.ErrorContains(t, err, "HTTP request failed after 2 attempts")
		require.Nil(t, httpResponse)
		require.Equal(t, 1, tokenSource.count)
	})
}

var _ TokenSource = &incrementingAuthTokenSource{}

type incrementingAuthTokenSource struct {
	count int
}

func (i *incrementingAuthTokenSource) Token(_ *http.Request, _ *url.URL, _ string, freshToken bool) (*Token, error) {
	if i.count == 0 {
		i.count = 1
	}
	if freshToken {
		i.count++
	}
	return &Token{
		AccessToken: "token" + strconv.Itoa(i.count),
		TokenType:   "Bearer",
	}, nil
}

var _ TokenSource = &noAuthTokenSource{}

type noAuthTokenSource struct {
}

func (n noAuthTokenSource) Token(httpRequest *http.Request, authzServerURL *url.URL, scope string, _ bool) (*Token, error) {
	return &Token{
		AccessToken: "token",
		TokenType:   "Bearer",
	}, nil
}
