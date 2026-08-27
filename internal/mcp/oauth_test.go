package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gurupraman/fieldlink/internal/policy"
)

// mockOIDCProvider is a real, minimal OIDC issuer for tests: it serves
// genuine discovery metadata and a genuine JWKS, and signs genuine RS256
// JWTs with its own key. newOIDCVerifier talks to it exactly as it would
// talk to Okta/Azure AD/Auth0/Keycloak — nothing here is a test double for
// the verification logic itself, only for the identity provider.
type mockOIDCProvider struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newMockOIDCProvider(t *testing.T) *mockOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &mockOIDCProvider{key: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":   p.srv.URL,
			"jwks_uri": p.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": p.kid,
					"use": "sig",
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(bigEndianBytes(key.PublicKey.E)),
				},
			},
		})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// bigEndianBytes returns the RSA public exponent as big-endian bytes.
// crypto/rsa.GenerateKey always produces E == 65537 (the standard F4
// exponent), so that's the only case this needs to handle.
func bigEndianBytes(e int) []byte {
	if e != 65537 {
		panic("unexpected RSA public exponent in test key")
	}
	return []byte{0x01, 0x00, 0x01}
}

// mint signs a JWT with claims controlled by the caller — used to build
// both valid tokens and deliberately-broken ones (wrong audience, expired,
// wrong signing key) for the rejection tests.
func (p *mockOIDCProvider) mint(t *testing.T, claims map[string]any, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestOIDCVerifier_AcceptsValidToken(t *testing.T) {
	p := newMockOIDCProvider(t)
	ctx := context.Background()

	verifier, err := newOIDCVerifier(ctx, OAuthOptions{IssuerURL: p.srv.URL, Audience: "fieldlink"})
	if err != nil {
		t.Fatalf("newOIDCVerifier: %v", err)
	}

	token := p.mint(t, map[string]any{
		"iss":   p.srv.URL,
		"aud":   "fieldlink",
		"sub":   "engineer-1",
		"scope": "fieldlink:read fieldlink:write",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}, p.key, p.kid)

	info, err := verifier(ctx, token, nil)
	if err != nil {
		t.Fatalf("verifier rejected a valid token: %v", err)
	}
	if info.UserID != "engineer-1" {
		t.Errorf("UserID = %q", info.UserID)
	}
	if len(info.Scopes) != 2 || info.Scopes[0] != "fieldlink:read" {
		t.Errorf("Scopes = %v", info.Scopes)
	}
}

func TestOIDCVerifier_RejectsWrongAudience(t *testing.T) {
	p := newMockOIDCProvider(t)
	ctx := context.Background()
	verifier, err := newOIDCVerifier(ctx, OAuthOptions{IssuerURL: p.srv.URL, Audience: "fieldlink"})
	if err != nil {
		t.Fatal(err)
	}

	token := p.mint(t, map[string]any{
		"iss": p.srv.URL, "aud": "some-other-service", "sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	}, p.key, p.kid)

	if _, err := verifier(ctx, token, nil); err == nil {
		t.Fatal("expected rejection for a token issued for a different audience")
	}
}

func TestOIDCVerifier_RejectsExpiredToken(t *testing.T) {
	p := newMockOIDCProvider(t)
	ctx := context.Background()
	verifier, err := newOIDCVerifier(ctx, OAuthOptions{IssuerURL: p.srv.URL, Audience: "fieldlink"})
	if err != nil {
		t.Fatal(err)
	}

	token := p.mint(t, map[string]any{
		"iss": p.srv.URL, "aud": "fieldlink", "sub": "x",
		"exp": time.Now().Add(-time.Hour).Unix(), "iat": time.Now().Add(-2 * time.Hour).Unix(),
	}, p.key, p.kid)

	if _, err := verifier(ctx, token, nil); err == nil {
		t.Fatal("expected rejection for an expired token")
	}
}

func TestOIDCVerifier_RejectsWrongSigningKey(t *testing.T) {
	p := newMockOIDCProvider(t)
	ctx := context.Background()
	verifier, err := newOIDCVerifier(ctx, OAuthOptions{IssuerURL: p.srv.URL, Audience: "fieldlink"})
	if err != nil {
		t.Fatal(err)
	}

	// Sign with a DIFFERENT key than the one published in the JWKS —
	// simulates a forged token or a compromised-but-unrelated key.
	forgedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token := p.mint(t, map[string]any{
		"iss": p.srv.URL, "aud": "fieldlink", "sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	}, forgedKey, p.kid)

	if _, err := verifier(ctx, token, nil); err == nil {
		t.Fatal("expected rejection for a token signed with the wrong key")
	}
}

func TestOIDCVerifier_RejectsMissingRequiredScope(t *testing.T) {
	p := newMockOIDCProvider(t)
	ctx := context.Background()
	verifier, err := newOIDCVerifier(ctx, OAuthOptions{
		IssuerURL: p.srv.URL, Audience: "fieldlink", RequiredScopes: []string{"fieldlink:admin"},
	})
	if err != nil {
		t.Fatal(err)
	}

	token := p.mint(t, map[string]any{
		"iss": p.srv.URL, "aud": "fieldlink", "sub": "x", "scope": "fieldlink:read",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	}, p.key, p.kid)

	if _, err := verifier(ctx, token, nil); err == nil {
		t.Fatal("expected rejection for a token missing the required scope")
	}
}

// TestHTTPTransport_OAuthEndToEnd drives a real fieldlink HTTP server
// configured for OAuth, through the actual RunHTTP path, with a real
// (mock) IdP — proving the full wire-up, not just newOIDCVerifier in
// isolation: the RFC 9728 discovery endpoint, the 401 without a token, and
// a successful call with a genuine signed token.
func TestHTTPTransport_OAuthEndToEnd(t *testing.T) {
	p := newMockOIDCProvider(t)

	ln := mustListen(t)
	addr := ln.Addr().String()
	resourceURL := "http://" + addr + "/mcp"

	s := New(policy.NewAllowAll(nil), nil)
	handler := gosdk.NewStreamableHTTPHandler(
		func(*http.Request) *gosdk.Server { return s }, &gosdk.StreamableHTTPOptions{},
	)

	verifier, err := newOIDCVerifier(context.Background(), OAuthOptions{IssuerURL: p.srv.URL, Audience: "fieldlink"})
	if err != nil {
		t.Fatal(err)
	}
	oauthOpts := OAuthOptions{IssuerURL: p.srv.URL, Audience: "fieldlink", ResourceURL: resourceURL}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/oauth-protected-resource", protectedResourceMetadataHandler(oauthOpts))
	mux.Handle("/mcp", sdkauth.RequireBearerToken(verifier, &sdkauth.RequireBearerTokenOptions{
		ResourceMetadataURL: resourceURL,
	})(handler))

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})

	// Discovery endpoint.
	resp, err := http.Get("http://" + addr + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	var meta map[string]any
	json.NewDecoder(resp.Body).Decode(&meta)
	resp.Body.Close()
	if meta["resource"] != resourceURL {
		t.Errorf("discovery resource = %v, want %v", meta["resource"], resourceURL)
	}

	// No token -> 401.
	resp2, err := http.Get("http://" + addr + "/mcp")
	if err != nil {
		t.Fatalf("GET /mcp: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status without token = %d, want 401", resp2.StatusCode)
	}

	// Valid token -> the request is authenticated (POST with a bogus body
	// will fail at the JSON-RPC layer, not at auth — that's the point:
	// proving auth passed and the request reached the MCP handler).
	token := p.mint(t, map[string]any{
		"iss": p.srv.URL, "aud": "fieldlink", "sub": "engineer-1",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	}, p.key, p.kid)
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp with valid token: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode == http.StatusUnauthorized {
		t.Fatal("a validly signed, correctly audienced token was rejected")
	}
}
