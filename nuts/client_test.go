package nuts

import (
	"context"
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-nuts-client/nuts/iam"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestOAuth2TokenSource_Token(t *testing.T) {
	t.Run("ok nodpop", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/internal/auth/v2/123abc/request-service-access-token", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"test","token_type":"Bearer","expires_in":3600}`))
		})
		httpServer := httptest.NewServer(mux)
		tokenSource := OAuth2TokenSource{
			NutsSubject: "123abc",
			NutsAPIURL:  httpServer.URL,
		}
		expectedAuthServerURL, _ := url.Parse("https://auth.example.com")
		httpRequest, _ := http.NewRequestWithContext(context.Background(), "GET", "https://resource.example.com", nil)

		token, err := tokenSource.Token(httpRequest, expectedAuthServerURL, "test")

		require.NoError(t, err)
		require.NotNil(t, token)

		require.Nil(t, token.DPoPToken)
		require.Equal(t, "test", token.AccessToken)
		require.Equal(t, "Bearer", token.TokenType)
		require.Greater(t, token.Expiry.Unix(), time.Now().Unix())
		require.Less(t, token.Expiry.Unix(), time.Now().Add(2*time.Hour).Unix())
	})
	t.Run("ok dpop", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/internal/auth/v2/123abc/request-service-access-token", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"test","token_type":"DPoP","expires_in":3600, "dpop_kid" : "kid"}`))
		})
		mux.HandleFunc("/internal/auth/v2/dpop/kid", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"dpop":"dpop321"}`))
		})
		httpServer := httptest.NewServer(mux)
		tokenSource := OAuth2TokenSource{
			NutsSubject: "123abc",
			NutsAPIURL:  httpServer.URL,
		}
		expectedAuthServerURL, _ := url.Parse("https://auth.example.com")
		httpRequest, _ := http.NewRequestWithContext(context.Background(), "GET", "https://resource.example.com", nil)

		token, err := tokenSource.Token(httpRequest, expectedAuthServerURL, "test")

		require.NoError(t, err)
		require.NotNil(t, token)

		require.NotNil(t, token.DPoPToken)
		require.Equal(t, "test", token.AccessToken)
		require.Equal(t, "DPoP", token.TokenType)
		require.Greater(t, token.Expiry.Unix(), time.Now().Unix())
		require.Less(t, token.Expiry.Unix(), time.Now().Add(2*time.Hour).Unix())
	})
	t.Run("additional credentials", func(t *testing.T) {
		mux := http.NewServeMux()
		var capturedRequest iam.ServiceAccessTokenRequest
		mux.HandleFunc("/internal/auth/v2/123abc/request-service-access-token", func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, json.NewDecoder(r.Body).Decode(&capturedRequest))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"test","token_type":"Bearer","expires_in":3600}`))
		})
		httpServer := httptest.NewServer(mux)
		tokenSource := OAuth2TokenSource{
			NutsSubject: "123abc",
			NutsAPIURL:  httpServer.URL,
		}
		expectedAuthServerURL, _ := url.Parse("https://auth.example.com")
		requestCtx := WithAdditionalCredentials(context.Background(), []vc.VerifiableCredential{
			{
				Issuer: ssi.MustParseURI("did:web:example.com"),
			},
		})
		httpRequest, _ := http.NewRequestWithContext(requestCtx, "GET", "https://resource.example.com", nil)

		token, err := tokenSource.Token(httpRequest, expectedAuthServerURL, "test")

		require.NoError(t, err)
		require.NotNil(t, token)

		require.Nil(t, token.DPoPToken)
		require.Equal(t, "test", token.AccessToken)
		require.Equal(t, "Bearer", token.TokenType)
		require.NotEmpty(t, capturedRequest.Credentials)
	})
	t.Run("error dpop with no kid", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/internal/auth/v2/123abc/request-service-access-token", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"test","token_type":"DPoP","expires_in":3600}`))
		})
		mux.HandleFunc("/internal/auth/v2/dpop/kid", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"dpop":"dpop321"}`))
		})
		httpServer := httptest.NewServer(mux)
		tokenSource := OAuth2TokenSource{
			NutsSubject: "123abc",
			NutsAPIURL:  httpServer.URL,
		}
		expectedAuthServerURL, _ := url.Parse("https://auth.example.com")
		httpRequest, _ := http.NewRequestWithContext(context.Background(), "GET", "https://resource.example.com", nil)

		_, err := tokenSource.Token(httpRequest, expectedAuthServerURL, "test")

		require.Error(t, err)
	})

	t.Run("error broken request-service-access-token", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/internal/auth/v2/123abc/request-service-access-token", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
		})
		httpServer := httptest.NewServer(mux)
		tokenSource := OAuth2TokenSource{
			NutsSubject: "123abc",
			NutsAPIURL:  httpServer.URL,
		}
		expectedAuthServerURL, _ := url.Parse("https://auth.example.com")
		httpRequest, _ := http.NewRequestWithContext(context.Background(), "GET", "https://resource.example.com", nil)

		_, err := tokenSource.Token(httpRequest, expectedAuthServerURL, "test")

		require.Error(t, err)
	})

	t.Run("error broken dpop call", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/internal/auth/v2/123abc/request-service-access-token", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"test","token_type":"DPoP","expires_in":3600, "dpop_kid" : "kid"}`))
		})
		mux.HandleFunc("/internal/auth/v2/dpop/kid", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`error`))
		})
		httpServer := httptest.NewServer(mux)
		tokenSource := OAuth2TokenSource{
			NutsSubject: "123abc",
			NutsAPIURL:  httpServer.URL,
		}
		expectedAuthServerURL, _ := url.Parse("https://auth.example.com")
		httpRequest, _ := http.NewRequestWithContext(context.Background(), "GET", "https://resource.example.com", nil)

		_, err := tokenSource.Token(httpRequest, expectedAuthServerURL, "test")

		require.Error(t, err)
	})
}
