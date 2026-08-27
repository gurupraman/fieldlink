package server

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

// OAuthOptions configures FieldLink as an OAuth 2.1 resource server
// (design.md's HTTP transport hardening, extended beyond a static bearer
// token): it validates access tokens issued by an external IdP — Okta,
// Azure AD, Auth0, Keycloak, anything speaking standard OIDC discovery —
// rather than issuing or managing tokens itself.
type OAuthOptions struct {
	IssuerURL      string
	Audience       string
	RequiredScopes []string
	// ResourceURL is this server's own URL (e.g. "https://gw:8765/mcp"),
	// echoed in the protected-resource metadata so compliant clients can
	// discover how to authenticate without being told out of band.
	ResourceURL string
}

// newOIDCVerifier builds a TokenVerifier backed by the IdP at
// opts.IssuerURL. It performs real OIDC discovery — fetching
// /.well-known/openid-configuration and then the JWKS it points to — so a
// misconfigured issuer URL fails fast at startup, not on the first
// request.
func newOIDCVerifier(ctx context.Context, opts OAuthOptions) (sdkauth.TokenVerifier, error) {
	provider, err := oidc.NewProvider(ctx, opts.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oauth: discovering issuer %s: %w", opts.IssuerURL, err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: opts.Audience})

	return func(ctx context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
		idToken, err := verifier.Verify(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", sdkauth.ErrInvalidToken, err)
		}

		var claims struct {
			Scope string `json:"scope"`
		}
		// Not every IdP includes a scope claim; a decode failure here
		// isn't fatal to the token's validity, just leaves Scopes empty.
		_ = idToken.Claims(&claims)
		scopes := splitScopes(claims.Scope)

		for _, required := range opts.RequiredScopes {
			if !slices.Contains(scopes, required) {
				return nil, fmt.Errorf("%w: missing required scope %q", sdkauth.ErrInvalidToken, required)
			}
		}

		return &sdkauth.TokenInfo{
			Scopes:     scopes,
			Expiration: idToken.Expiry,
			UserID:     idToken.Subject,
		}, nil
	}, nil
}

func splitScopes(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// protectedResourceMetadataHandler serves RFC 9728 discovery metadata so
// spec-compliant MCP clients can find and use opts.IssuerURL automatically
// instead of requiring a human to hand-configure an Authorization header.
func protectedResourceMetadataHandler(opts OAuthOptions) http.Handler {
	return sdkauth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:             opts.ResourceURL,
		AuthorizationServers: []string{opts.IssuerURL},
		ScopesSupported:      opts.RequiredScopes,
	})
}
