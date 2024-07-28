package oauth2

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ProtectedResourceMetadataLocator tries to load the OAuth2 Authorization Server URL for a resource server,
// using protected resource metadata provided by the resource server.
// It tries to locate the URL of the resource metadata using the following options:
//   - resource URI specified in request context
//   - WWW-Authenticate header in the response (specified by the draft RFC).
func ProtectedResourceMetadataLocator(metadataLoader *MetadataLoader, response *http.Response) (*url.URL, error) {
	var metadataURL *url.URL
	var err error
	if resourceURI, ok := response.Request.Context().Value(resourceURIContextKey).(string); ok {
		metadataURL, err = url.Parse(resourceURI)
		if err != nil {
			return nil, err
		}
		metadataURL = metadataURL.JoinPath(".well-known/oauth-protected-resource")
	} else {
		metadataURL = ParseProtectedResourceMetadataURL(response)
	}
	if metadataURL == nil {
		return nil, nil
	}
	var metadata ProtectedResourceMetadata
	if err := metadataLoader.Load(metadataURL.String(), &metadata); err != nil {
		return nil, fmt.Errorf("OAuth2 protected resource metadata fetch failed (url=%s): %w", metadataURL, err)
	}
	if len(metadata.AuthorizationServers) != 1 {
		// TODO: Might have to support more in future
		return nil, fmt.Errorf("expected exactly one authorization server, got %d", len(metadata.AuthorizationServers))
	}
	result, err := url.Parse(metadata.AuthorizationServers[0])
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ParseProtectedResourceMetadataURL returns the URL of the protected resource metadata according to https://www.ietf.org/archive/id/draft-ietf-oauth-resource-metadata-07.html,
// if the HTTP response contains a WWW-Authenticate header according to the specification.
// If the header is not present, does not contain the WWW-Authenticate header or the header does not contain the protected resource metadata URL, nil is returned.
func ParseProtectedResourceMetadataURL(response *http.Response) *url.URL {
	header := response.Header.Get("WWW-Authenticate")
	if len(header) == 0 {
		return nil
	}
	// Header is in the form of:
	//   WWW-Authenticate: Bearer error="invalid_request",
	//    error_description="No access token was provided in this request",
	//    resource_metadata=
	//    "https://resource.example.com/.well-known/oauth-protected-resource"
	// Remove first word of the header (e.g. Bearer or DPoP)
	spaceIdx := strings.Index(header, " ")
	if spaceIdx == -1 {
		return nil
	}
	header = strings.TrimSpace(header[spaceIdx:])
	// Find the resource_metadata parameter in the comma, separated list of key-value pairs.
	for _, kv := range splitCommaSeparatedList(header) {
		key, value, ok := splitKeyVal(kv)
		if ok && key == "resource_metadata" {
			if u, err := url.Parse(value); err == nil {
				return u
			}
		}
	}
	return nil
}

func splitKeyVal(s string) (key, value string, ok bool) {
	// credits to copilot
	i := strings.Index(s, "=")
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), strings.Trim(strings.TrimSpace(s[i+1:]), "\""), true
}

func splitCommaSeparatedList(s string) []string {
	// credits to copilot
	var res []string
	var b strings.Builder
	escaped := false
	for _, r := range s {
		if r == '\\' {
			escaped = true
			continue
		}
		if r == ',' && !escaped {
			res = append(res, b.String())
			b.Reset()
			continue
		}
		if escaped {
			escaped = false
		}
		b.WriteRune(r)
	}
	res = append(res, b.String())
	return res
}
