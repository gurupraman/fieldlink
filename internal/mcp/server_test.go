package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gurupraman/fieldlink/internal/grant"
	"github.com/gurupraman/fieldlink/internal/policy"
)

// TestServeReadFileAndListDirectory exercises the server the way a real MCP
// client does: initialize, tools/list, tools/call — over an in-memory
// transport pair, against a real file on disk. This is the "Claude Code can
// add fieldlink and read a file through it" bar from HANDOFF.md, automated.
func TestServeReadFileAndListDirectory(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello from fieldlink"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	s := New(policy.NewAllowAll(nil), nil)

	serverTransport, clientTransport := gosdk.NewInMemoryTransports()

	serverSession, err := s.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer serverSession.Close()

	client := gosdk.NewClient(&gosdk.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer clientSession.Close()

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	names := map[string]bool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = true
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("tool %q missing readOnlyHint:true", tool.Name)
		}
	}
	if !names["read_file"] || !names["list_directory"] {
		t.Fatalf("expected read_file and list_directory in tools/list, got %v", names)
	}

	readResult, err := clientSession.CallTool(ctx, &gosdk.CallToolParams{
		Name:      "read_file",
		Arguments: map[string]any{"path": filePath},
	})
	if err != nil {
		t.Fatalf("tools/call read_file: %v", err)
	}
	if readResult.IsError {
		t.Fatalf("read_file returned isError: %+v", readResult.Content)
	}
	var readOut struct {
		Content string `json:"content"`
	}
	if b, err := json.Marshal(readResult.StructuredContent); err == nil {
		json.Unmarshal(b, &readOut)
	}
	if readOut.Content != "hello from fieldlink" {
		t.Fatalf("read_file content = %q, want %q", readOut.Content, "hello from fieldlink")
	}

	listResult, err := clientSession.CallTool(ctx, &gosdk.CallToolParams{
		Name:      "list_directory",
		Arguments: map[string]any{"path": dir},
	})
	if err != nil {
		t.Fatalf("tools/call list_directory: %v", err)
	}
	if listResult.IsError {
		t.Fatalf("list_directory returned isError: %+v", listResult.Content)
	}
	var listOut struct {
		Entries []struct {
			Name string `json:"name"`
		} `json:"entries"`
	}
	if b, err := json.Marshal(listResult.StructuredContent); err == nil {
		json.Unmarshal(b, &listOut)
	}
	if len(listOut.Entries) != 1 || listOut.Entries[0].Name != "hello.txt" {
		t.Fatalf("list_directory entries = %+v, want one entry named hello.txt", listOut.Entries)
	}

	// A denied read must come back as isError:true in a successful
	// JSON-RPC result, never a protocol-level error (design.md §4.3).
	deniedResult, err := clientSession.CallTool(ctx, &gosdk.CallToolParams{
		Name:      "read_file",
		Arguments: map[string]any{"path": filepath.Join(dir, "does-not-exist.txt")},
	})
	if err != nil {
		t.Fatalf("tools/call read_file (missing): %v", err)
	}
	if !deniedResult.IsError {
		t.Fatalf("expected isError:true for a missing file, got %+v", deniedResult)
	}
}

// TestMissingGrantYieldsZeroTools is the Week 2 done-bar from CLAUDE.md's
// build order: "An unsigned grant yields zero advertised tools."
func TestMissingGrantYieldsZeroTools(t *testing.T) {
	dir := t.TempDir()
	// No grant.yaml, no grant.yaml.sig, no trusted.pub were ever written.
	eng := policy.NewGrantEngine("fieldlink-test",
		filepath.Join(dir, "grant.yaml"), filepath.Join(dir, "trusted.pub"), nil)

	ctx := context.Background()
	s := New(eng, nil)

	serverTransport, clientTransport := gosdk.NewInMemoryTransports()
	serverSession, err := s.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer serverSession.Close()

	client := gosdk.NewClient(&gosdk.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer clientSession.Close()

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if len(tools.Tools) != 0 {
		t.Fatalf("expected zero tools with no grant present, got %v", toolNames(tools.Tools))
	}
}

// TestGrantFiltersToolsByCapability proves tools/list reflects exactly the
// grant's capability set, not "everything this build implements" — a grant
// covering only fs.read must not advertise list_directory.
func TestGrantFiltersToolsByCapability(t *testing.T) {
	dir := t.TempDir()
	eng := signedGrantEngine(t, dir, `
version: 1
grant_id: 01J9Z8Q7K3M4N5P6R7S8T9V0W1
agent_id: fieldlink-test
issued_at: `+time.Now().Add(-1*time.Hour).UTC().Format(time.RFC3339)+`
expires_at: `+time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339)+`
issuer: security@example.com
capabilities:
  - capability: fs.read
    constraints:
      paths: ["`+filepath.ToSlash(dir)+`/**"]
`)

	ctx := context.Background()
	s := New(eng, nil)

	serverTransport, clientTransport := gosdk.NewInMemoryTransports()
	serverSession, err := s.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer serverSession.Close()

	client := gosdk.NewClient(&gosdk.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer clientSession.Close()

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	names := toolNames(tools.Tools)
	if len(names) != 1 || !names["read_file"] {
		t.Fatalf("expected only read_file, got %v", names)
	}
}

func toolNames(tools []*gosdk.Tool) map[string]bool {
	names := map[string]bool{}
	for _, tool := range tools {
		names[tool.Name] = true
	}
	return names
}

// signedGrantEngine signs grantYAML with a fresh throwaway keypair and
// writes grant.yaml, grant.yaml.sig, and trusted.pub into dir, returning a
// ready-to-use policy.GrantEngine.
func signedGrantEngine(t *testing.T, dir, grantYAML string) *policy.GrantEngine {
	t.Helper()
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
	if err := grant.WriteSignatureFile(grantPath+".sig", sig); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "trusted.pub")
	if err := grant.WritePublicKeyFile(pubPath, pub); err != nil {
		t.Fatal(err)
	}

	return policy.NewGrantEngine("fieldlink-test", grantPath, pubPath, nil)
}
