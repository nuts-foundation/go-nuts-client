package oauth2

import (
	"context"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestParseProtectedResourceMetadataURL(t *testing.T) {
	expected, _ := url.Parse("https://resource.example.com/.well-known/oauth-protected-resource")
	t.Run("ok", func(t *testing.T) {
		input := &http.Response{
			Header: http.Header{
				"Www-Authenticate": []string{
					`Bearer error="invalid_request", error_description="No access token was provided in this request", resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"`,
				},
			},
		}
		actual := ParseProtectedResourceMetadataURL(input)
		require.Equal(t, expected, actual)
	})
	t.Run("no WWW-Authenticate header", func(t *testing.T) {
		input := &http.Response{}
		actual := ParseProtectedResourceMetadataURL(input)
		require.Nil(t, actual)
	})
	t.Run("WWW-Authenticate header contains escaped quotes", func(t *testing.T) {
		input := &http.Response{
			Header: http.Header{
				"Www-Authenticate": []string{
					`Bearer error="invalid_request", error_description="No access\" token was provided in this request", resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"`,
				},
			},
		}
		actual := ParseProtectedResourceMetadataURL(input)
		require.Equal(t, expected, actual)
	})
	t.Run("WWW-Authenticate header contains commas in values", func(t *testing.T) {
		input := &http.Response{
			Header: http.Header{
				"Www-Authenticate": []string{
					`Bearer error="invalid_request", error_description="No access, token was provided in this,request",, resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"`,
				},
			},
		}
		actual := ParseProtectedResourceMetadataURL(input)
		require.Equal(t, expected, actual)
	})
}

func TestProtectedResourceMetadataLocator(t *testing.T) {
	t.Run("resource URI passed in context", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/oauth-protected-resource", func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(`{"resource":"https://resource.example.com/.well-known/oauth-protected-resource", "authorization_servers": ["https://example.com/auth"]}`))
		})
		httpServer := httptest.NewServer(mux)

		ctx := WithResourceURI(context.Background(), httpServer.URL)
		httpRequest, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com", nil)
		inputResponse := &http.Response{Request: httpRequest}
		actual, err := ProtectedResourceMetadataLocator(&MetadataLoader{
			Client: http.DefaultClient,
		}, inputResponse)

		require.NoError(t, err)
		require.Equal(t, "https://example.com/auth", actual.String())
	})
	t.Run("WWW-Authenticate header", func(t *testing.T) {
		t.Run("fully qualified URL", func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/.well-known/oauth-protected-resource", func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Add("Content-Type", "application/json")
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write([]byte(`{"resource":"https://resource.example.com/.well-known/oauth-protected-resource", "authorization_servers": ["https://example.com/auth"]}`))
			})
			httpServer := httptest.NewServer(mux)

			inputResponse := &http.Response{
				Request: httptest.NewRequest(http.MethodGet, "https://example.com", nil),
				Header: http.Header{
					"Www-Authenticate": []string{
						`Bearer resource_metadata="` + httpServer.URL + `/.well-known/oauth-protected-resource"`,
					},
				},
			}
			actual, err := ProtectedResourceMetadataLocator(&MetadataLoader{
				Client: http.DefaultClient,
			}, inputResponse)

			require.NoError(t, err)
			require.Equal(t, "https://example.com/auth", actual.String())
		})
		t.Run("relative URL", func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/foo/.well-known/oauth-protected-resource", func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Add("Content-Type", "application/json")
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write([]byte(`{"resource":"/foo", "authorization_servers": ["https://example.com/auth"]}`))
			})
			httpServer := httptest.NewServer(mux)

			inputResponse := &http.Response{
				Request: httptest.NewRequest(http.MethodGet, httpServer.URL+"/some/resource", nil),
				Header: http.Header{
					"Www-Authenticate": []string{
						`Bearer resource_metadata="/foo/.well-known/oauth-protected-resource"`,
					},
				},
			}
			actual, err := ProtectedResourceMetadataLocator(&MetadataLoader{
				Client: http.DefaultClient,
			}, inputResponse)

			require.NoError(t, err)
			require.Equal(t, "https://example.com/auth", actual.String())
		})
	})
}
