// This file implements FieldLink's optional built-in OAuth authorization
// server: a minimal, config-defined client-credentials token issuer for
// operators with no external identity provider (design.md's OAuth support
// otherwise requires one — Okta, Azure AD, Auth0, Keycloak, anything
// speaking OIDC discovery).
//
// Deliberately narrow scope, stated up front: no user accounts, no login
// UI, no dynamic client registration, no refresh tokens. Clients are a
// static config.yaml list, same shape as everything else FieldLink treats
// as trusted configuration (datasources, devices, SMB shares). This is not
// a general-purpose identity platform — CLAUDE.md rules that out
// explicitly — it is the smallest thing that lets "no IdP" operators still
// get real, short-lived, per-client-revocable tokens instead of one
// forever-valid shared string.
//
// It reuses newOIDCVerifier unchanged: FieldLink serves standard OIDC
// discovery + JWKS for itself, and the resource-server verification code
// that checks tokens from Okta doesn't know or care that this issuer is
// local. One verification path, not two.
package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	josejwk "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

const defaultLocalIssuerTTL = 15 * time.Minute

// LocalIssuerOptions configures the built-in token issuer.
type LocalIssuerOptions struct {
	SigningKeyPath string
	TokenTTL       time.Duration
	Clients        map[string]LocalIssuerClientOptions
	// SelfURL is FieldLink's own externally-reachable base URL (e.g.
	// "https://gw:8765"), used as both the issuer and audience, and to
	// build the discovery/JWKS/token endpoint URLs.
	SelfURL string
	// RequiredScopes must all be present in a token's scope claim for a
	// /mcp request to be accepted (checked on verification, independent
	// of what a client requested at token-issuance time).
	RequiredScopes []string
}

type LocalIssuerClientOptions struct {
	Secret string
	Scopes []string
}

type localIssuer struct {
	key            *rsa.PrivateKey
	kid            string
	ttl            time.Duration
	clients        map[string]LocalIssuerClientOptions
	selfURL        string
	requiredScopes []string
}

// newLocalIssuer loads or generates the issuer's signing key and returns a
// ready-to-mount handler set.
func newLocalIssuer(opts LocalIssuerOptions) (*localIssuer, error) {
	if len(opts.Clients) == 0 {
		return nil, fmt.Errorf("local_issuer: at least one client must be configured")
	}
	key, err := loadOrGenerateIssuerKey(opts.SigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("local_issuer: %w", err)
	}
	ttl := opts.TokenTTL
	if ttl <= 0 {
		ttl = defaultLocalIssuerTTL
	}
	return &localIssuer{
		key:            key,
		kid:            "fieldlink-local-issuer-1",
		ttl:            ttl,
		clients:        opts.Clients,
		selfURL:        opts.SelfURL,
		requiredScopes: opts.RequiredScopes,
	}, nil
}

// loadOrGenerateIssuerKey reads an RSA key from path, or generates and
// persists a fresh one if the file doesn't exist yet — the same
// generate-on-first-run pattern as the grant signing key, except this key
// stays on the host (see LocalIssuerConfig's doc comment for why that's
// safe here).
func loadOrGenerateIssuerKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("signing key %s is not valid PEM", path)
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func (li *localIssuer) discoveryHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                   li.selfURL,
			"jwks_uri":                 li.selfURL + "/oauth/jwks",
			"token_endpoint":           li.selfURL + "/oauth/token",
			"grant_types_supported":    []string{"client_credentials"},
			"response_types_supported": []string{"token"},
		})
	})
}

func (li *localIssuer) jwksHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		set := josejwk.JSONWebKeySet{Keys: []josejwk.JSONWebKey{
			{
				Key:       &li.key.PublicKey,
				KeyID:     li.kid,
				Algorithm: "RS256",
				Use:       "sig",
			},
		}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(set)
	})
}

// tokenHandler implements the client-credentials grant (RFC 6749 §4.4):
// POST with client_id/client_secret (HTTP Basic or form body, both
// standard) and an optional space-separated scope, returns a signed
// access_token.
func (li *localIssuer) tokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			clientID = r.PostForm.Get("client_id")
			clientSecret = r.PostForm.Get("client_secret")
		}
		if r.PostForm.Get("grant_type") != "client_credentials" {
			writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type")
			return
		}

		client, ok := li.clients[clientID]
		if !ok || subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) != 1 {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client")
			return
		}

		requested := splitScopes(r.PostForm.Get("scope"))
		var granted []string
		for _, s := range requested {
			if slices.Contains(client.Scopes, s) {
				granted = append(granted, s)
			}
		}
		if len(requested) == 0 {
			granted = client.Scopes // no scope requested -> grant everything this client is allowed
		}

		now := time.Now()
		claims := jwt.MapClaims{
			"iss":   li.selfURL,
			"aud":   li.selfURL,
			"sub":   clientID,
			"scope": joinScopes(granted),
			"iat":   now.Unix(),
			"exp":   now.Add(li.ttl).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = li.kid
		signed, err := token.SignedString(li.key)
		if err != nil {
			http.Error(w, "token signing failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": signed,
			"token_type":   "Bearer",
			"expires_in":   int(li.ttl.Seconds()),
			"scope":        joinScopes(granted),
		})
	})
}

func writeOAuthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func joinScopes(scopes []string) string {
	out := ""
	for i, s := range scopes {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

// verifierOptions builds the OAuthOptions needed to validate tokens this
// issuer mints, pointed at itself as the issuer.
func (li *localIssuer) verifierOptions() OAuthOptions {
	return OAuthOptions{
		IssuerURL:      li.selfURL,
		Audience:       li.selfURL,
		RequiredScopes: li.requiredScopes,
		ResourceURL:    li.selfURL + "/mcp",
	}
}
