package grant

import (
	"strings"
	"testing"
	"time"
)

const validYAML = `
version: 1
grant_id: 01J9Z8Q7K3M4N5P6R7S8T9V0W1
agent_id: fieldlink-test
issued_at: 2026-01-01T00:00:00Z
expires_at: 2026-03-01T00:00:00Z
issuer: security@example.com
capabilities:
  - capability: fs.read
    constraints:
      paths: ["/tmp/**/*.csv"]
      max_bytes: 1048576
`

func TestParseAndValidate(t *testing.T) {
	g, canonical, err := ParseYAML([]byte(validYAML))
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(canonical) == 0 {
		t.Fatal("canonical bytes are empty")
	}
	if g.AgentID != "fieldlink-test" {
		t.Errorf("AgentID = %q", g.AgentID)
	}
	constraints, ok := g.Find("fs.read")
	if !ok {
		t.Fatal("fs.read not found")
	}
	if constraints["max_bytes"].(float64) != 1048576 {
		t.Errorf("max_bytes = %v", constraints["max_bytes"])
	}
	if _, ok := g.Find("fs.list"); ok {
		t.Error("fs.list should not be present")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	_, canonical, err := ParseYAML([]byte(validYAML))
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}

	sig := Sign(priv, canonical)
	if !Verify(pub, canonical, sig) {
		t.Fatal("Verify failed on an untampered signature")
	}
}

func TestVerifyRejectsTamperedDocument(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	_, canonical, err := ParseYAML([]byte(validYAML))
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}
	sig := Sign(priv, canonical)

	tampered := []byte(strings.Replace(string(canonical), "fieldlink-test", "fieldlink-other", 1))
	if Verify(pub, tampered, sig) {
		t.Fatal("Verify accepted a tampered document")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	otherPub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	_, canonical, err := ParseYAML([]byte(validYAML))
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}
	sig := Sign(priv, canonical)

	if Verify(otherPub, canonical, sig) {
		t.Fatal("Verify accepted a signature from a different key")
	}
}

func TestValidateRejectsMissingExpiry(t *testing.T) {
	g := &Grant{Version: 1, GrantID: "x", AgentID: "a"}
	if err := g.Validate(); err == nil {
		t.Fatal("expected error for missing expires_at")
	}
}

func TestValidateRejectsExpiryBeyond180Days(t *testing.T) {
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g := &Grant{
		Version:   1,
		GrantID:   "x",
		AgentID:   "a",
		IssuedAt:  issued,
		ExpiresAt: issued.Add(181 * 24 * time.Hour),
	}
	if err := g.Validate(); err == nil {
		t.Fatal("expected error for expiry beyond 180 days")
	}
}

func TestValidateRejectsUnsupportedVersion(t *testing.T) {
	g := &Grant{
		Version:   2,
		GrantID:   "x",
		AgentID:   "a",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := g.Validate(); err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestKeyFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	pubPath := dir + "/trusted.pub"
	privPath := dir + "/signing.key"
	if err := WritePublicKeyFile(pubPath, pub); err != nil {
		t.Fatalf("WritePublicKeyFile: %v", err)
	}
	if err := WritePrivateKeyFile(privPath, priv); err != nil {
		t.Fatalf("WritePrivateKeyFile: %v", err)
	}

	gotPub, err := ReadPublicKeyFile(pubPath)
	if err != nil {
		t.Fatalf("ReadPublicKeyFile: %v", err)
	}
	if !gotPub.Equal(pub) {
		t.Fatal("public key round-trip mismatch")
	}

	gotPriv, err := ReadPrivateKeyFile(privPath)
	if err != nil {
		t.Fatalf("ReadPrivateKeyFile: %v", err)
	}
	if !gotPriv.Equal(priv) {
		t.Fatal("private key round-trip mismatch")
	}
}

func TestSignatureFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	_, canonical, err := ParseYAML([]byte(validYAML))
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}
	sig := Sign(priv, canonical)

	sigPath := dir + "/grant.yaml.sig"
	if err := WriteSignatureFile(sigPath, sig); err != nil {
		t.Fatalf("WriteSignatureFile: %v", err)
	}
	gotSig, err := ReadSignatureFile(sigPath)
	if err != nil {
		t.Fatalf("ReadSignatureFile: %v", err)
	}
	if string(gotSig) != string(sig) {
		t.Fatal("signature round-trip mismatch")
	}
}
