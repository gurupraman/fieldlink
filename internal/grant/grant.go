// Package grant implements the offline-signed capability grant described in
// docs/design.md §6: parsing, RFC 8785 canonicalization, and Ed25519
// sign/verify. It has no knowledge of the filesystem or of MCP — that
// belongs to internal/policy, which is the actual trust boundary.
package grant

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gowebpki/jcs"
	"gopkg.in/yaml.v3"
)

// domainSeparator prevents a signature produced for this scheme from being
// replayed as if it were valid for another (design.md §6.4).
const domainSeparator = "fieldlink-grant-v1:"

// maxValidity is the mandatory upper bound on expires_at - issued_at.
const maxValidity = 180 * 24 * time.Hour

// SupportedVersion is the only grant document version this build accepts.
const SupportedVersion = 1

type Grant struct {
	Version      int               `yaml:"version" json:"version"`
	GrantID      string            `yaml:"grant_id" json:"grant_id"`
	AgentID      string            `yaml:"agent_id" json:"agent_id"`
	IssuedAt     time.Time         `yaml:"issued_at" json:"issued_at"`
	ExpiresAt    time.Time         `yaml:"expires_at" json:"expires_at"`
	Issuer       string            `yaml:"issuer" json:"issuer"`
	Capabilities []CapabilityGrant `yaml:"capabilities" json:"capabilities"`
}

type CapabilityGrant struct {
	Capability  string         `yaml:"capability" json:"capability"`
	Constraints map[string]any `yaml:"constraints" json:"constraints"`
}

// Find returns the constraints for capability, and whether it is present.
func (g *Grant) Find(capability string) (map[string]any, bool) {
	for _, c := range g.Capabilities {
		if c.Capability == capability {
			return c.Constraints, true
		}
	}
	return nil, false
}

// Validate enforces the mandatory shape rules from design.md §6.4. It does
// not check the signature or the current time against ExpiresAt — that is
// Verify's and the caller's job respectively, so Validate can also be used
// to reject a malformed document before it is ever signed.
func (g *Grant) Validate() error {
	if g.Version != SupportedVersion {
		return fmt.Errorf("unsupported grant version %d (want %d)", g.Version, SupportedVersion)
	}
	if g.GrantID == "" {
		return fmt.Errorf("grant_id is required")
	}
	if g.AgentID == "" {
		return fmt.Errorf("agent_id is required")
	}
	if g.ExpiresAt.IsZero() {
		return fmt.Errorf("expires_at is required")
	}
	if !g.IssuedAt.IsZero() && g.ExpiresAt.Before(g.IssuedAt) {
		return fmt.Errorf("expires_at is before issued_at")
	}
	if !g.IssuedAt.IsZero() && g.ExpiresAt.Sub(g.IssuedAt) > maxValidity {
		return fmt.Errorf("expires_at is more than %s after issued_at", maxValidity)
	}
	return nil
}

// ParseYAML parses a grant document and also returns its RFC 8785 canonical
// JSON form — the exact bytes that were (or must be) signed.
func ParseYAML(data []byte) (*Grant, []byte, error) {
	// Decode into a generic, JSON-compatible value first so canonical
	// bytes reflect exactly what was authored, independent of Grant's Go
	// field set — a signature must cover the whole document, including
	// any future fields this build doesn't know about.
	var generic any
	if err := yaml.Unmarshal(data, &generic); err != nil {
		return nil, nil, fmt.Errorf("parse grant yaml: %w", err)
	}

	rawJSON, err := json.Marshal(generic)
	if err != nil {
		return nil, nil, fmt.Errorf("grant yaml is not JSON-representable: %w", err)
	}

	canonical, err := jcs.Transform(rawJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("canonicalize grant: %w", err)
	}

	var g Grant
	if err := json.Unmarshal(rawJSON, &g); err != nil {
		return nil, nil, fmt.Errorf("grant yaml does not match the expected shape: %w", err)
	}

	return &g, canonical, nil
}

// SigningBytes returns the exact bytes an offline key signs: the domain
// separator followed by the canonical document.
func SigningBytes(canonicalJSON []byte) []byte {
	return append([]byte(domainSeparator), canonicalJSON...)
}

// Sign signs canonicalJSON (as produced by ParseYAML) with priv.
func Sign(priv ed25519.PrivateKey, canonicalJSON []byte) []byte {
	return ed25519.Sign(priv, SigningBytes(canonicalJSON))
}

// Verify reports whether sig is a valid signature over canonicalJSON by pub.
func Verify(pub ed25519.PublicKey, canonicalJSON, sig []byte) bool {
	return ed25519.Verify(pub, SigningBytes(canonicalJSON), sig)
}
