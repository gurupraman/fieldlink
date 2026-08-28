package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gurupraman/fieldlink/internal/audit"
	"github.com/gurupraman/fieldlink/internal/config"
	"github.com/gurupraman/fieldlink/internal/grant"
	"github.com/gurupraman/fieldlink/internal/policy"
)

// TestAuditAttributesCallToOAuthClient is the real end-to-end proof that a
// call made over HTTP with a local_issuer token gets attributed to that
// specific client in the audit log — not just to the installation's
// agent_id. It exercises the full real stack: a real signed grant, a real
// GrantEngine with a real audit.Chain, a real RunHTTP server in
// local_issuer mode, a real minted token, and a real MCP tool call over
// the wire — then reads the actual audit.jsonl file back and checks it.
func TestAuditAttributesCallToOAuthClient(t *testing.T) {
	rawDir := t.TempDir()
	// Resolve symlinks up front (macOS symlinks /var -> /private/var, so
	// t.TempDir() and the path the executor resolves via
	// filepath.EvalSymlinks otherwise disagree) — the grant's glob must
	// match what the executor actually checks against, same as every
	// other test in this codebase that builds a path-scoped grant.
	dir, err := filepath.EvalSymlinks(rawDir)
	if err != nil {
		t.Fatal(err)
	}

	// A file the grant will permit reading.
	filePath := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A real signed grant covering fs.read for this directory.
	grantYAML := `
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
	pub, priv, err := grant.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	g, canonical, err := grant.ParseYAML([]byte(grantYAML))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	sig := grant.Sign(priv, canonical)
	grantPath := filepath.Join(dir, "grant.yaml")
	os.WriteFile(grantPath, []byte(grantYAML), 0o644)
	grant.WriteSignatureFile(grantPath+".sig", sig)
	pubPath := filepath.Join(dir, "trusted.pub")
	grant.WritePublicKeyFile(pubPath, pub)

	eng := policy.NewGrantEngine("fieldlink-test", grantPath, pubPath, nil)

	auditPath := filepath.Join(dir, "audit.jsonl")
	chain, err := audit.Open(auditPath, "fieldlink-test")
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	eng.Audit = chain

	s := New(eng, &config.Config{})

	addr := "127.0.0.1:18790"
	selfURL := "http://" + addr
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunHTTP(ctx, s, HTTPOptions{
			Bind: addr,
			LocalIssuer: &LocalIssuerOptions{
				SigningKeyPath: filepath.Join(dir, "issuer.key"),
				SelfURL:        selfURL,
				Clients: map[string]LocalIssuerClientOptions{
					"engineer-laptop": {Secret: "s3cret", Scopes: []string{"fieldlink:read"}},
				},
			},
		})
	}()
	waitForServer(t, addr)

	tok, err := requestToken(selfURL, "engineer-laptop", "s3cret", "fieldlink:read")
	if err != nil {
		t.Fatalf("requestToken: %v", err)
	}

	// A real MCP client, over real HTTP, authenticated with the minted
	// token, making a real tools/call.
	client := gosdk.NewClient(&gosdk.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	httpClient := &http.Client{Transport: bearerRoundTripper{token: tok.AccessToken, next: http.DefaultTransport}}
	cs, err := client.Connect(context.Background(), &gosdk.StreamableClientTransport{
		Endpoint: selfURL + "/mcp", HTTPClient: httpClient,
	}, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	result, err := cs.CallTool(context.Background(), &gosdk.CallToolParams{
		Name:      "read_file",
		Arguments: map[string]any{"path": filePath},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("read_file was denied: %+v", result.Content)
	}

	cancel()
	<-errCh
	chain.Close()

	// Now inspect the real audit file for the attribution.
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var rec audit.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("unmarshal audit record: %v", err)
		}
		if rec.Capability == "fs.read" && rec.Decision == "allow" {
			if rec.CallerID != "engineer-laptop" {
				t.Fatalf("fs.read allow record has caller_id %q, want %q", rec.CallerID, "engineer-laptop")
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no fs.read allow record found in audit log:\n%s", data)
	}
}
