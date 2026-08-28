package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gurupraman/fieldlink/internal/policy"
)

func TestLocalIssuerKey_PersistsAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "issuer.key")

	key1, err := loadOrGenerateIssuerKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrGenerateIssuerKey (generate): %v", err)
	}
	key2, err := loadOrGenerateIssuerKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrGenerateIssuerKey (reload): %v", err)
	}
	if !key1.Equal(key2) {
		t.Fatal("reloading the same path produced a different key — tokens issued before a restart would stop verifying")
	}
}

func TestLocalIssuer_RejectsEmptyClientList(t *testing.T) {
	dir := t.TempDir()
	_, err := newLocalIssuer(LocalIssuerOptions{
		SigningKeyPath: filepath.Join(dir, "k.pem"),
		SelfURL:        "http://127.0.0.1:1",
		Clients:        nil,
	})
	if err == nil {
		t.Fatal("expected an error for a local_issuer with no clients configured")
	}
}

// TestHTTPTransport_LocalIssuerEndToEnd drives the actual RunHTTP path in
// local_issuer mode: real key generation, a real HTTP POST to /oauth/token
// with client credentials, a real signed JWT that comes back, and a real
// /mcp call authenticated with it. This is the scenario an operator with no
// external IdP actually runs.
func TestHTTPTransport_LocalIssuerEndToEnd(t *testing.T) {
	dir := t.TempDir()
	addr := "127.0.0.1:18770"
	selfURL := "http://" + addr

	s := New(policy.NewAllowAll(nil), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunHTTP(ctx, s, HTTPOptions{
			Bind: addr,
			LocalIssuer: &LocalIssuerOptions{
				SigningKeyPath: filepath.Join(dir, "issuer.key"),
				TokenTTL:       2 * time.Minute,
				SelfURL:        selfURL,
				Clients: map[string]LocalIssuerClientOptions{
					"engineer-laptop": {Secret: "correct-horse-battery-staple", Scopes: []string{"fieldlink:read"}},
				},
			},
		})
	}()
	waitForServer(t, addr)

	// 1. Wrong secret is rejected.
	if _, err := requestToken(selfURL, "engineer-laptop", "wrong-secret", ""); err == nil {
		t.Fatal("expected token request with wrong secret to fail")
	}

	// 2. Correct credentials mint a real token.
	tok, err := requestToken(selfURL, "engineer-laptop", "correct-horse-battery-staple", "fieldlink:read")
	if err != nil {
		t.Fatalf("requestToken: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("expected a non-empty access_token")
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", tok.TokenType)
	}

	// 3. That token authenticates a real /mcp request.
	req, _ := http.NewRequest(http.MethodGet, selfURL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /mcp with issued token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatal("a token freshly issued by the local issuer was rejected by its own verifier")
	}

	// 4. An unknown client is rejected outright.
	if _, err := requestToken(selfURL, "nobody", "whatever", ""); err == nil {
		t.Fatal("expected token request for an unconfigured client to fail")
	}

	// 5. Discovery and JWKS are real and self-consistent.
	discResp, err := http.Get(selfURL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	var disc map[string]any
	json.NewDecoder(discResp.Body).Decode(&disc)
	discResp.Body.Close()
	if disc["issuer"] != selfURL {
		t.Errorf("discovery issuer = %v, want %v", disc["issuer"], selfURL)
	}

	jwksResp, err := http.Get(selfURL + "/oauth/jwks")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	var jwks map[string]any
	json.NewDecoder(jwksResp.Body).Decode(&jwks)
	jwksResp.Body.Close()
	keys, _ := jwks["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %d", len(keys))
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("RunHTTP: %v", err)
	}
}

// TestHTTPTransport_LocalIssuerEnforcesRequiredScope proves a token that
// doesn't carry a scope the server requires is rejected at the /mcp layer,
// even though the token itself is validly signed and unexpired.
func TestHTTPTransport_LocalIssuerEnforcesRequiredScope(t *testing.T) {
	dir := t.TempDir()
	addr := "127.0.0.1:18771"
	selfURL := "http://" + addr

	s := New(policy.NewAllowAll(nil), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunHTTP(ctx, s, HTTPOptions{
			Bind: addr,
			LocalIssuer: &LocalIssuerOptions{
				SigningKeyPath: filepath.Join(dir, "issuer.key"),
				SelfURL:        selfURL,
				RequiredScopes: []string{"fieldlink:admin"},
				Clients: map[string]LocalIssuerClientOptions{
					"readonly-client": {Secret: "s3cret", Scopes: []string{"fieldlink:read"}}, // no admin scope
				},
			},
		})
	}()
	waitForServer(t, addr)

	tok, err := requestToken(selfURL, "readonly-client", "s3cret", "fieldlink:read")
	if err != nil {
		t.Fatalf("requestToken: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, selfURL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /mcp: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 401/403 for a token missing the required scope", resp.StatusCode)
	}

	cancel()
	<-errCh
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func requestToken(baseURL, clientID, clientSecret, scope string) (*tokenResponse, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	if scope != "" {
		form.Set("scope", scope)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d", resp.StatusCode)
	}
	var tok tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, err
	}
	return &tok, nil
}

func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := (&http.Client{Timeout: 50 * time.Millisecond}).Get("http://" + addr + "/oauth/jwks")
		if err == nil {
			conn.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s never became ready", addr)
}
