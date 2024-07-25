package oauth2

import (
	"net/url"
	"time"
)

type Token struct {
	AccessToken string
	TokenType   string
	Expiry      *time.Time
}

type TokenSource interface {
	Token(authzServerURL *url.URL, requestedResource *url.URL, scope string) (*Token, error)
}
