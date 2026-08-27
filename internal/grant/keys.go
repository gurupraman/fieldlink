package grant

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// GenerateKeyPair creates a fresh Ed25519 signing key. The private half must
// never be written anywhere near a FieldLink host (design.md §6.2) — callers
// are responsible for that discipline; this function just generates bytes.
func GenerateKeyPair() (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	return ed25519.GenerateKey(rand.Reader)
}

// WritePublicKeyFile writes pub in the trusted.pub format: a comment header
// followed by one line of standard base64.
func WritePublicKeyFile(path string, pub ed25519.PublicKey) error {
	var buf bytes.Buffer
	buf.WriteString("# fieldlink trusted signing key (Ed25519, base64)\n")
	buf.WriteString(base64.StdEncoding.EncodeToString(pub))
	buf.WriteString("\n")
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// WritePrivateKeyFile writes priv as raw base64. Callers must treat the
// resulting file as the single most sensitive artifact in the project: it
// signs grants, and a grant is the entire trust boundary.
func WritePrivateKeyFile(path string, priv ed25519.PrivateKey) error {
	var buf bytes.Buffer
	buf.WriteString("# fieldlink signing key (Ed25519, base64) — OFFLINE USE ONLY\n")
	buf.WriteString("# Never copy this file to a FieldLink host.\n")
	buf.WriteString(base64.StdEncoding.EncodeToString(priv))
	buf.WriteString("\n")
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// ReadPublicKeyFile reads a trusted.pub file, skipping comment (#) and blank
// lines.
func ReadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	line, err := firstDataLine(data)
	if err != nil {
		return nil, fmt.Errorf("read public key %s: %w", path, err)
	}
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return nil, fmt.Errorf("public key %s is not valid base64: %w", path, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key %s has %d bytes, want %d", path, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// ReadPrivateKeyFile reads a signing key file written by WritePrivateKeyFile.
func ReadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	line, err := firstDataLine(data)
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", path, err)
	}
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return nil, fmt.Errorf("private key %s is not valid base64: %w", path, err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key %s has %d bytes, want %d", path, len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

// WriteSignatureFile writes sig as the sole content of a grant.yaml.sig file.
func WriteSignatureFile(path string, sig []byte) error {
	return os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644)
}

// ReadSignatureFile reads a grant.yaml.sig file.
func ReadSignatureFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	line, err := firstDataLine(data)
	if err != nil {
		return nil, fmt.Errorf("read signature %s: %w", path, err)
	}
	sig, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return nil, fmt.Errorf("signature %s is not valid base64: %w", path, err)
	}
	return sig, nil
}

// Fingerprint returns a short, stable identifier for a public key, safe to
// log at startup (design.md §6.4: "its fingerprint is logged at every
// startup").
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return fmt.Sprintf("sha256:%x", sum[:8])
}

func firstDataLine(data []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line, nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no data line found")
}
