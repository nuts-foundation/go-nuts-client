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
	t.Run("ok", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/internal/auth/v2/did:web:example.com/request-service-access-token", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"test","token_type":"bearer","expires_in":3600}`))
		})
		httpServer := httptest.NewServer(mux)
		tokenSource := OAuth2TokenSource{
			OwnDID:     "did:web:example.com",
			NutsAPIURL: httpServer.URL,
		}
		expectedAuthServerURL, _ := url.Parse("https://auth.example.com")
		httpRequest, _ := http.NewRequestWithContext(context.Background(), "GET", "https://resource.example.com", nil)

		token, err := tokenSource.Token(httpRequest, expectedAuthServerURL, "test")

		require.NoError(t, err)
		require.NotNil(t, token)

		require.Equal(t, "test", token.AccessToken)
		require.Equal(t, "bearer", token.TokenType)
		require.Greater(t, token.Expiry.Unix(), time.Now().Unix())
		require.Less(t, token.Expiry.Unix(), time.Now().Add(2*time.Hour).Unix())
	})
	t.Run("additional credentials", func(t *testing.T) {
		mux := http.NewServeMux()
		var capturedRequest iam.ServiceAccessTokenRequest
		mux.HandleFunc("/internal/auth/v2/did:web:example.com/request-service-access-token", func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, json.NewDecoder(r.Body).Decode(&capturedRequest))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"test","token_type":"bearer","expires_in":3600}`))
		})
		httpServer := httptest.NewServer(mux)
		tokenSource := OAuth2TokenSource{
			OwnDID:     "did:web:example.com",
			NutsAPIURL: httpServer.URL,
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

		require.Equal(t, "test", token.AccessToken)
		require.Equal(t, "bearer", token.TokenType)
		require.NotEmpty(t, capturedRequest.Credentials)
	})
}
