package oauth2

import (
	"bytes"
	"context"
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
type AuthorizationServerLocator func(metadataLoader *MetadataLoader, response *http.Response) (*url.URL, error)

// StaticAuthorizationServerURL returns an AuthorizationServerLocator that always returns the same URL.
func StaticAuthorizationServerURL(u *url.URL) AuthorizationServerLocator {
	return func(_ *MetadataLoader, _ *http.Response) (*url.URL, error) {
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

type Transport struct {
	TokenSource         TokenSource
	MetadataLoader      *MetadataLoader
	Scope               string
	UnderlyingTransport http.RoundTripper
	AuthzServerLocators []AuthorizationServerLocator
}

func (o *Transport) RoundTrip(httpRequest *http.Request) (*http.Response, error) {
	var err error
	var client http.RoundTripper
	if o.UnderlyingTransport == nil {
		client = http.DefaultTransport
	} else {
		client = o.UnderlyingTransport
	}
	// Work with a buffered request body, as we often need to retry the request.
	var requestBody []byte
	if httpRequest.Body != nil {
		requestBody, err = io.ReadAll(httpRequest.Body)
		if err != nil {
			return nil, err
		}
	}

	httpRequest = copyRequest(httpRequest, requestBody)
	httpResponse, err := client.RoundTrip(httpRequest)
	if err != nil {
		return nil, err
	}
	if httpResponse.StatusCode == http.StatusUnauthorized {
		token, err := o.requestToken(httpRequest, httpResponse)
		if err != nil {
			return nil, fmt.Errorf("OAuth2 token request (resource=%s): %w", httpRequest.URL.String(), err)
		}
		httpRequest = copyRequest(httpRequest, requestBody)
		httpRequest.Header.Set("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.AccessToken))
		httpResponse, err = client.RoundTrip(httpRequest)
	}
	return httpResponse, err
}

func (o *Transport) requestToken(httpRequest *http.Request, httpResponse *http.Response) (*Token, error) {
	var authzServerURL *url.URL
	var err error
	for _, locator := range o.AuthzServerLocators {
		authzServerURL, err = locator(o.MetadataLoader, httpResponse)
		if authzServerURL != nil {
			break
		}
	}
	if authzServerURL == nil {
		return nil, errors.New("couldn't determine the correct Authorization Server")
	}

	// Use the scope from the request context if available.
	scope := o.Scope
	if ctxScope, ok := httpRequest.Context().Value(withScopeContextKeyInstance).(string); ok {
		scope = ctxScope
	}

	token, err := o.TokenSource.Token(httpRequest, authzServerURL, scope)
	if err != nil {
		return nil, err
	}
	return token, err
}

func copyRequest(request *http.Request, body []byte) *http.Request {
	request = request.Clone(request.Context())
	if len(body) > 0 {
		request.Body = io.NopCloser(bytes.NewReader(body))
	}
	return request
}

// WithScope returns a new context with the given OAuth2 scope.
func WithScope(ctx context.Context, scope string) context.Context {
	return context.WithValue(ctx, withScopeContextKeyInstance, scope)
}

type withScopeContextKey struct{}

var withScopeContextKeyInstance = withScopeContextKey{}
