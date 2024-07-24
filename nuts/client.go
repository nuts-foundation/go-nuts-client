package nuts

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-nuts-client/nuts/iam"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

type CredentialProvider interface {
	Credentials() []vc.VerifiableCredential
}

type Config struct {
	OwnDID                string
	NutsHttpClient        HttpRequestDoer
	NutsAPIURL            string
	AdditionalCredentials CredentialProvider
	Context               context.Context
	authServerURL         string
}

type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// OAuth2Client returns a http.Client that authenticates to the OAuth2 remote Resource Server with Nuts OAuth2 access tokens.
// It only supports service access tokens (client credentials flow, no OpenID4VP) at the moment.
// It will use the API of a local Nuts node to request the access token.
func OAuth2Client(authServerURL string, nutsAPIURL string, ownDID string) *http.Client {
	return OAuth2ClientWithConfig(Config{
		OwnDID:        ownDID,
		NutsAPIURL:    nutsAPIURL,
		authServerURL: authServerURL,
	})
}

func OAuth2ClientWithConfig(config Config) *http.Client {
	if config.NutsHttpClient == nil {
		config.NutsHttpClient = http.DefaultClient
	}
	return oauth2.NewClient(config.Context, &tokenSource{
		config: config,
	})
}

var _ oauth2.TokenSource = &tokenSource{}

type tokenSource struct {
	config Config
}

func (t tokenSource) Token() (*oauth2.Token, error) {
	if t.config.OwnDID == "" {
		return nil, fmt.Errorf("ownDID is required")
	}
	if t.config.authServerURL == "" {
		return nil, fmt.Errorf("metadata URL is required")
	}
	client, err := iam.NewClient(t.config.NutsAPIURL)
	if err != nil {
		return nil, err
	}
	var ctx = t.config.Context
	if ctx == nil {
		ctx = context.Background()
	}
	var additionalCredentials []vc.VerifiableCredential
	if t.config.AdditionalCredentials != nil {
		additionalCredentials = t.config.AdditionalCredentials.Credentials()
	}
	// TODO: Might want to support DPoP as well
	var tokenType = iam.ServiceAccessTokenRequestTokenTypeBearer
	response, err := client.RequestServiceAccessToken(ctx, t.config.OwnDID, iam.RequestServiceAccessTokenJSONRequestBody{
		AuthorizationServer: t.config.authServerURL,
		Credentials:         &additionalCredentials,
		Scope:               "",
		TokenType:           &tokenType,
	})
	if err != nil {
		return nil, err
	}
	accessTokenResponse, err := iam.ParseRequestServiceAccessTokenResponse(response)
	if err != nil {
		return nil, err
	}
	if accessTokenResponse.JSON200 == nil {
		return nil, fmt.Errorf("failed service access token response: %s", accessTokenResponse.HTTPResponse.Status)
	}
	if accessTokenResponse.JSON200.ExpiresIn == nil {
		return nil, fmt.Errorf("missing expires_in in service access token response")
	}
	expiry := time.Now().Add(time.Duration(*accessTokenResponse.JSON200.ExpiresIn) * time.Second)
	return &oauth2.Token{
		AccessToken: accessTokenResponse.JSON200.AccessToken,
		TokenType:   accessTokenResponse.JSON200.TokenType,
		Expiry:      expiry,
	}, nil
}
