package nuts

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-nuts-client/nuts/iam"
	"github.com/nuts-foundation/go-nuts-client/oauth2"
	"net/http"
	"net/url"
	"time"
)

type CredentialProvider interface {
	Credentials() []vc.VerifiableCredential
}

// TokenSource returns an oauth2.TokenSource that authenticates to the OAuth2 remote Resource Server with Nuts OAuth2 access tokens.
// It only supports service access tokens (client credentials flow, no OpenID4VP) at the moment.
// It will use the API of a local Nuts node to request the access token.
func TokenSource(nutsAPIURL string, ownDID string) *OAuth2TokenSource {
	return &OAuth2TokenSource{}
}

var _ oauth2.TokenSource = &OAuth2TokenSource{}

type OAuth2TokenSource struct {
	OwnDID string
	// NutsAPIURL is the base URL of the Nuts node API.
	NutsAPIURL string
	// Context is the context used for the HTTP requests to the Nuts node.
	// If not set, context.Background() is used.
	Context context.Context
	// AdditionalCredentials are additional credentials that are used to request the service access token.
	AdditionalCredentials CredentialProvider
	// NutsHttpClient is the HTTP client used to communicate with the Nuts node.
	// If not set, http.DefaultClient is used.
	NutsHttpClient *http.Client
}

func (o OAuth2TokenSource) Token(authzServerURL *url.URL, requestedResource *url.URL, scope string) (*oauth2.Token, error) {
	if o.OwnDID == "" {
		return nil, fmt.Errorf("ownDID is required")
	}
	var ctx = o.Context
	if ctx == nil {
		ctx = context.Background()
	}
	var additionalCredentials []vc.VerifiableCredential
	if o.AdditionalCredentials != nil {
		additionalCredentials = o.AdditionalCredentials.Credentials()
	}
	client, err := iam.NewClient(o.NutsAPIURL)
	if err != nil {
		return nil, err
	}
	// TODO: Might want to support DPoP as well
	var tokenType = iam.ServiceAccessTokenRequestTokenTypeBearer
	response, err := client.RequestServiceAccessToken(ctx, o.OwnDID, iam.RequestServiceAccessTokenJSONRequestBody{
		AuthorizationServer: authzServerURL.String(),
		Credentials:         &additionalCredentials,
		Scope:               scope,
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
	var expiry *time.Time
	if accessTokenResponse.JSON200.ExpiresIn != nil {
		expiry = new(time.Time)
		*expiry = time.Now().Add(time.Duration(*accessTokenResponse.JSON200.ExpiresIn) * time.Second)
	}
	return &oauth2.Token{
		AccessToken: accessTokenResponse.JSON200.AccessToken,
		TokenType:   accessTokenResponse.JSON200.TokenType,
		Expiry:      expiry,
	}, nil
}
