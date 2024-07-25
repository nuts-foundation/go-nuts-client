package oauth2

import (
	"github.com/stretchr/testify/require"
	"net/http"
	"net/url"
	"testing"
)

func TestParseProtectedResourceMetadataURL(t *testing.T) {
	expected, _ := url.Parse("https://resource.example.com/.well-known/oauth-protected-resource")
	t.Run("ok", func(t *testing.T) {
		input := http.Response{
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
		input := http.Response{}
		actual := ParseProtectedResourceMetadataURL(input)
		require.Nil(t, actual)
	})
	t.Run("WWW-Authenticate header contains escaped quotes", func(t *testing.T) {
		input := http.Response{
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
		input := http.Response{
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
