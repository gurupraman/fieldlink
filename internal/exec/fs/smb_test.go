package fs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gurupraman/fieldlink/internal/config"
	"github.com/gurupraman/fieldlink/internal/grant"
	"github.com/gurupraman/fieldlink/internal/policy"
)

// These tests run against a real local Samba server, started separately
// with:
//
//	mkdir -p /tmp/smb-test-share
//	echo "hello from an smb share" > /tmp/smb-test-share/hello.txt
//	docker run -d --name fieldlink-smb-test -p 1445:445 \
//	  -v /tmp/smb-test-share:/share dperson/samba -p \
//	  -u "testuser;testpass" -s "exports;/share;yes;no;no;testuser"
//
// Skipped automatically if FIELDLINK_TEST_SMB_HOST isn't set.
func testSMBExecutor(t *testing.T, pathGlob string) *Executor {
	t.Helper()
	host := os.Getenv("FIELDLINK_TEST_SMB_HOST")
	if host == "" {
		t.Skip("FIELDLINK_TEST_SMB_HOST not set; skipping live Samba test")
	}
	os.Setenv("FIELDLINK_TEST_SMB_USER", "testuser")
	os.Setenv("FIELDLINK_TEST_SMB_PASS", "testpass")

	eng := grantedSMBEngine(t, pathGlob)
	shares := map[string]config.SMBShare{
		"exports": {
			Host: host, Port: 1445, Share: "exports",
			UsernameEnv: "FIELDLINK_TEST_SMB_USER", PasswordEnv: "FIELDLINK_TEST_SMB_PASS",
		},
	}
	return &Executor{Policy: eng, SMBShares: shares}
}

func grantedSMBEngine(t *testing.T, pathGlob string) policy.Engine {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := grant.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	yaml := `
version: 1
grant_id: 01J9Z8Q7K3M4N5P6R7S8T9V0W1
agent_id: fieldlink-test
issued_at: ` + time.Now().Add(-1*time.Hour).UTC().Format(time.RFC3339) + `
expires_at: ` + time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339) + `
issuer: security@example.com
capabilities:
  - capability: fs.read
    constraints:
      paths: ["` + pathGlob + `"]
      max_bytes: 1048576
  - capability: fs.list
    constraints:
      paths: ["` + pathGlob + `"]
      recursive: true
`
	g, canonical, err := grant.ParseYAML([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	sig := grant.Sign(priv, canonical)

	grantPath := filepath.Join(dir, "grant.yaml")
	if err := os.WriteFile(grantPath, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := grant.WriteSignatureFile(grantPath+".sig", sig); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "trusted.pub")
	if err := grant.WritePublicKeyFile(pubPath, pub); err != nil {
		t.Fatal(err)
	}
	return policy.NewGrantEngine("fieldlink-test", grantPath, pubPath, nil)
}

func TestSMB_RealServer_ReadFile(t *testing.T) {
	exec := testSMBExecutor(t, "smb://exports/**")

	result, out, err := exec.ReadFile(context.Background(), nil, ReadFileInput{
		Path: "smb://exports/hello.txt",
	})
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if result != nil && result.IsError {
		t.Fatalf("ReadFile denied: %+v", result.Content)
	}
	if out.Content != "hello from an smb share\n" {
		t.Fatalf("content = %q", out.Content)
	}
}

func TestSMB_RealServer_ListDirectory(t *testing.T) {
	exec := testSMBExecutor(t, "smb://exports/**")

	result, out, err := exec.ListDirectory(context.Background(), nil, ListDirectoryInput{
		Path: "smb://exports/",
	})
	if err != nil {
		t.Fatalf("ListDirectory: %v", err)
	}
	if result != nil && result.IsError {
		t.Fatalf("ListDirectory denied: %+v", result.Content)
	}
	names := map[string]bool{}
	for _, e := range out.Entries {
		names[e.Name] = true
	}
	if !names["hello.txt"] || !names["data.csv"] {
		t.Fatalf("expected hello.txt and data.csv, got %v", names)
	}
}

func TestSMB_RealServer_DeniesOutsideGrant(t *testing.T) {
	// Grant only covers a different, unrelated share glob.
	exec := testSMBExecutor(t, "smb://other-share/**")

	result, _, err := exec.ReadFile(context.Background(), nil, ReadFileInput{
		Path: "smb://exports/hello.txt",
	})
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true for a share outside the grant")
	}
}

func TestSMB_RealServer_RejectsPathTraversal(t *testing.T) {
	exec := testSMBExecutor(t, "smb://exports/**")

	result, _, err := exec.ReadFile(context.Background(), nil, ReadFileInput{
		Path: "smb://exports/../../etc/passwd",
	})
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true for a path traversal attempt")
	}
}
