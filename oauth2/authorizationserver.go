package oauth2

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type AuthorizationServerMetadata struct {
	// AuthorizationEndpoint is the URL of the OAuth2 Authorization Endpoint.
	AuthorizationEndpoint string `json:"authorization_endpoint"`
}

// ProtectedResourceMetadata contains metadata about a protected resource according to https://www.ietf.org/archive/id/draft-ietf-oauth-resource-metadata-07.html
type ProtectedResourceMetadata struct {
	// Resource contains the protected resource's resource identifier, which is a URL that uses the https scheme and has no query or fragment components.
	Resource string `json:"resource"`
	// AuthorizationServers contains a JSON array containing a list of OAuth authorization server issuer identifiers,
	// as defined in [RFC8414], for authorization servers that can be used with this protected resource.
	// Protected resources MAY choose not to advertise some supported authorization servers even when this parameter is used.
	// In some use cases, the set of authorization servers will not be enumerable, in which case this metadata parameter would not be used.
	AuthorizationServers []string `json:"authorization_servers"`
	// BearerMethodsSupported contains a JSON array containing a list of the supported methods of sending an OAuth 2.0 Bearer Token [RFC6750]
	// to the protected resource. Defined values are ["header", "body", "query"], corresponding to Sections 2.1, 2.2, and 2.3 of RFC 6750.
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

// MetadataLoader loads metadata from a URL and unmarshals it into a target struct.
// TODO: add caching
type MetadataLoader struct {
	Client HttpRequestDoer
}

func (m MetadataLoader) Load(metadataUrl string, target interface{}) error {
	client := m.Client
	if client == nil {
		client = http.DefaultClient
	}
	httpResponse, err := http.Get(metadataUrl)
	if err != nil {
		return fmt.Errorf("metadata fetch (url=%s): %w", metadataUrl, err)
	}
	defer httpResponse.Body.Close()
	responseData, err := io.ReadAll(io.LimitReader(httpResponse.Body, 1<<20)) // 10mb
	if err != nil {
		return fmt.Errorf("metadata read (url=%s): %w", metadataUrl, err)
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		return fmt.Errorf("metadata fetch (url=%s): %s", metadataUrl, responseData)
	}
	err = json.Unmarshal(responseData, target)
	if err != nil {
		return fmt.Errorf("metadata parse (url=%s): %w", metadataUrl, err)
	}
	return nil
}
