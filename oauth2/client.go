package oauth2

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// AuthorizationServerLocator is a function that determines the URL of the OAuth2 Authorization Server from an OAuth2 Resource Server response.
// If the Authorization Server URL cannot be determined, the function returns nil.
type AuthorizationServerLocator func(metadataLoader *MetadataLoader, response http.Response) (*url.URL, error)

// StaticAuthorizationServerURL returns an AuthorizationServerLocator that always returns the same URL.
func StaticAuthorizationServerURL(u *url.URL) AuthorizationServerLocator {
	return func(_ *MetadataLoader, _ http.Response) (*url.URL, error) {
		return u, nil
	}
}

var _ http.RoundTripper = &Transport{}

func NewClient(tokenSource TokenSource, scope string) *http.Client {
	return &http.Client{
		Transport: &Transport{
			TokenSource:    tokenSource,
			Scope:          scope,
			MetadataLoader: &MetadataLoader{},
			AuthzServerLocators: []AuthorizationServerLocator{
				ProtectedResourceMetadataLocator,
			},
		},
	}
}

type tokenCacheKey struct {
	resourceServer string
	scope          string
}

type Transport struct {
	TokenSource         TokenSource
	MetadataLoader      *MetadataLoader
	Scope               string
	UnderlyingTransport http.RoundTripper
	AuthzServerLocators []AuthorizationServerLocator
}

func (o *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	var err error
	var client http.RoundTripper
	if o.UnderlyingTransport == nil {
		client = http.DefaultTransport
	} else {
		client = o.UnderlyingTransport
	}
	httpResponse, err := client.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if httpResponse.StatusCode == http.StatusUnauthorized {
		token, err := o.requestToken(httpResponse, request.URL)
		if err != nil {
			return nil, fmt.Errorf("OAuth2 token request (resource=%s): %w", request.URL.String(), err)
		}
		request, err = requestWithToken(request, token)
		if err != nil {
			return nil, err
		}
		httpResponse, err = client.RoundTrip(request)
	}
	return httpResponse, err
}

func (o *Transport) requestToken(httpResponse *http.Response, resourceURL *url.URL) (*Token, error) {
	var authzServerURL *url.URL
	var err error
	for _, locator := range o.AuthzServerLocators {
		authzServerURL, err = locator(o.MetadataLoader, *httpResponse)
		if authzServerURL != nil {
			break
		}
	}
	if authzServerURL == nil {
		return nil, errors.New("couldn't determine the correct Authorization Server")
	}

	token, err := o.TokenSource.Token(authzServerURL, resourceURL, o.Scope)
	if err != nil {
		return nil, err
	}
	return token, err
}

func requestWithToken(request *http.Request, token *Token) (*http.Request, error) {
	request = request.Clone(request.Context())
	if request.Body != nil {
		requestBody, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		request.Body = io.NopCloser(bytes.NewReader(requestBody))
	}
	// Set the Authorization header
	request.Header.Set("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))
	return request, nil
}
