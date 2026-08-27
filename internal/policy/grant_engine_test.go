package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gurupraman/fieldlink/internal/grant"
)

// testFixture signs grantYAML with a fresh keypair and writes grant.yaml,
// grant.yaml.sig, and trusted.pub into a temp dir, returning a ready-to-use
// GrantEngine plus the dir (for callers that want real paths to authorize
// against).
func testFixture(t *testing.T, grantYAML string) (*GrantEngine, string) {
	t.Helper()
	dir := t.TempDir()

	pub, priv, err := grant.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	g, canonical, err := grant.ParseYAML([]byte(grantYAML))
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	sig := grant.Sign(priv, canonical)

	grantPath := filepath.Join(dir, "grant.yaml")
	if err := os.WriteFile(grantPath, []byte(grantYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := grant.WriteSignatureFile(sigPathFor(grantPath), sig); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "trusted.pub")
	if err := grant.WritePublicKeyFile(pubPath, pub); err != nil {
		t.Fatal(err)
	}

	eng := NewGrantEngine("fieldlink-test", grantPath, pubPath, nil)
	return eng, dir
}

func validGrantYAML(t *testing.T, dir string) string {
	t.Helper()
	return `
version: 1
grant_id: 01J9Z8Q7K3M4N5P6R7S8T9V0W1
agent_id: fieldlink-test
issued_at: ` + time.Now().Add(-1*time.Hour).UTC().Format(time.RFC3339) + `
expires_at: ` + time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339) + `
issuer: security@example.com
capabilities:
  - capability: fs.read
    constraints:
      paths: ["` + filepath.ToSlash(dir) + `/**"]
      max_bytes: 1048576
`
}

func TestGrantEngine_AllowsMatchingCapability(t *testing.T) {
	dir := t.TempDir()
	eng, fdir := testFixture(t, validGrantYAML(t, dir))
	_ = fdir

	if !eng.Granted("fs.read") {
		t.Fatal("expected fs.read to be granted")
	}
	if eng.Granted("fs.list") {
		t.Fatal("fs.list should not be granted")
	}

	decision := eng.Authorize(context.Background(), "fs.read", map[string]any{
		"path": dir + "/data.csv",
	})
	if !decision.Allowed {
		t.Fatalf("expected allow, got deny: %s", decision.Reason)
	}
}

func TestGrantEngine_DeniesPathOutsideGlob(t *testing.T) {
	dir := t.TempDir()
	eng, _ := testFixture(t, validGrantYAML(t, dir))

	decision := eng.Authorize(context.Background(), "fs.read", map[string]any{
		"path": "/etc/shadow",
	})
	if decision.Allowed {
		t.Fatal("expected deny for a path outside the grant")
	}
	if decision.Reason == "" {
		t.Fatal("expected a reason")
	}
}

func TestGrantEngine_DeniesCapabilityAbsentFromGrant(t *testing.T) {
	dir := t.TempDir()
	eng, _ := testFixture(t, validGrantYAML(t, dir))

	decision := eng.Authorize(context.Background(), "fs.list", map[string]any{"path": dir})
	if decision.Allowed {
		t.Fatal("expected deny for an ungranted capability")
	}
}

func TestGrantEngine_DeniesExpiredGrant(t *testing.T) {
	dir := t.TempDir()
	expired := `
version: 1
grant_id: 01J9Z8Q7K3M4N5P6R7S8T9V0W1
agent_id: fieldlink-test
issued_at: ` + time.Now().Add(-48*time.Hour).UTC().Format(time.RFC3339) + `
expires_at: ` + time.Now().Add(-1*time.Hour).UTC().Format(time.RFC3339) + `
issuer: security@example.com
capabilities:
  - capability: fs.read
    constraints:
      paths: ["` + filepath.ToSlash(dir) + `/**"]
`
	// Validate() would reject expires_at < issued_at check only if
	// expires_at is before issued_at, which is not the case here, so this
	// signs fine; the engine must reject it at load() on the expiry check.
	eng, _ := testFixtureNoValidate(t, expired)

	if eng.Granted("fs.read") {
		t.Fatal("an expired grant must not report any capability as granted")
	}
	decision := eng.Authorize(context.Background(), "fs.read", map[string]any{"path": dir + "/x"})
	if decision.Allowed {
		t.Fatal("expected deny for an expired grant")
	}
}

func TestGrantEngine_DeniesWrongAgentID(t *testing.T) {
	dir := t.TempDir()
	wrongAgent := `
version: 1
grant_id: 01J9Z8Q7K3M4N5P6R7S8T9V0W1
agent_id: some-other-installation
issued_at: ` + time.Now().Add(-1*time.Hour).UTC().Format(time.RFC3339) + `
expires_at: ` + time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339) + `
issuer: security@example.com
capabilities:
  - capability: fs.read
    constraints:
      paths: ["` + filepath.ToSlash(dir) + `/**"]
`
	eng, _ := testFixture(t, wrongAgent)
	if eng.Granted("fs.read") {
		t.Fatal("a grant issued for a different agent_id must not be honored")
	}
}

func TestGrantEngine_DeniesTamperedGrantFile(t *testing.T) {
	dir := t.TempDir()
	eng, fdir := testFixture(t, validGrantYAML(t, dir))

	// Tamper with the grant document after it was signed.
	grantPath := filepath.Join(fdir, "grant.yaml")
	data, err := os.ReadFile(grantPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append(data, []byte("\n  - capability: fs.list\n    constraints: {}\n")...)
	if err := os.WriteFile(grantPath, tampered, 0o644); err != nil {
		t.Fatal(err)
	}

	if eng.Granted("fs.list") {
		t.Fatal("a tampered grant must fail signature verification, not grant new capabilities")
	}
}

func TestGrantEngine_FailsClosedOnMissingGrant(t *testing.T) {
	dir := t.TempDir()
	eng := NewGrantEngine("fieldlink-test", filepath.Join(dir, "does-not-exist.yaml"), filepath.Join(dir, "does-not-exist.pub"), nil)

	if eng.Granted("fs.read") {
		t.Fatal("a missing grant must grant nothing")
	}
	decision := eng.Authorize(context.Background(), "fs.read", map[string]any{"path": "/tmp/x"})
	if decision.Allowed {
		t.Fatal("a missing grant must authorize nothing")
	}
}

// testFixtureNoValidate is like testFixture but skips grant.Validate() so
// tests can construct grants that are signable but semantically invalid at
// runtime (e.g. already expired).
func testFixtureNoValidate(t *testing.T, grantYAML string) (*GrantEngine, string) {
	t.Helper()
	dir := t.TempDir()

	pub, priv, err := grant.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	_, canonical, err := grant.ParseYAML([]byte(grantYAML))
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}
	sig := grant.Sign(priv, canonical)

	grantPath := filepath.Join(dir, "grant.yaml")
	if err := os.WriteFile(grantPath, []byte(grantYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := grant.WriteSignatureFile(sigPathFor(grantPath), sig); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "trusted.pub")
	if err := grant.WritePublicKeyFile(pubPath, pub); err != nil {
		t.Fatal(err)
	}

	return NewGrantEngine("fieldlink-test", grantPath, pubPath, nil), dir
}
