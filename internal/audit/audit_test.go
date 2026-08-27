package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendAndVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	c, err := Open(path, "fieldlink-test")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := c.Append("g1", "fs.read", "allow", "", ParamsDigest(map[string]any{"path": "/tmp/x"})); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := c.Append("g1", "fs.list", "deny", "path is not permitted", ParamsDigest(map[string]any{"path": "/etc"})); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	res, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected a valid chain, got: %s", res.BrokenReason)
	}
	if res.RecordCount != 2 {
		t.Errorf("RecordCount = %d, want 2", res.RecordCount)
	}
}

func TestVerifyDetectsTamperedField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	c, err := Open(path, "fieldlink-test")
	if err != nil {
		t.Fatal(err)
	}
	c.Append("g1", "fs.read", "allow", "", ParamsDigest(nil))
	c.Append("g1", "fs.read", "deny", "denied", ParamsDigest(nil))
	c.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip the second record's decision from "deny" to "allow" without
	// recomputing its hash — exactly what an attacker editing the file
	// directly would do.
	tampered := strings.Replace(string(data), `"decision":"deny"`, `"decision":"allow"`, 1)
	if tampered == string(data) {
		t.Fatal("test setup: replacement did not match anything in the file")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("expected Verify to detect the tampered record")
	}
	if res.BrokenAtSeq != 2 {
		t.Errorf("BrokenAtSeq = %d, want 2", res.BrokenAtSeq)
	}
}

func TestVerifyDetectsTruncatedChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	c, err := Open(path, "fieldlink-test")
	if err != nil {
		t.Fatal(err)
	}
	c.Append("g1", "fs.read", "allow", "", ParamsDigest(nil))
	c.Append("g1", "fs.read", "allow", "", ParamsDigest(nil))
	c.Append("g1", "fs.read", "allow", "", ParamsDigest(nil))
	c.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	// Delete the middle record entirely (not just edit it) — a truncation
	// attack, not just a field edit.
	rewritten := lines[0] + "\n" + lines[2] + "\n"
	if err := os.WriteFile(path, []byte(rewritten), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatal("expected Verify to detect the deleted record")
	}
}

func TestChainResumesAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	c1, err := Open(path, "fieldlink-test")
	if err != nil {
		t.Fatal(err)
	}
	c1.Append("g1", "fs.read", "allow", "", ParamsDigest(nil))
	c1.Close()

	// Simulate a process restart: a fresh Chain opened against the same
	// file must continue the sequence and hash chain, not reset to seq 1
	// with an empty prev_hash (which would silently break continuity).
	c2, err := Open(path, "fieldlink-test")
	if err != nil {
		t.Fatal(err)
	}
	c2.Append("g1", "fs.read", "allow", "", ParamsDigest(nil))
	c2.Close()

	res, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected a valid chain across restart, got: %s", res.BrokenReason)
	}
	if res.RecordCount != 2 {
		t.Errorf("RecordCount = %d, want 2", res.RecordCount)
	}
}

func TestParamsDigestNeverEmbedsRawParams(t *testing.T) {
	digest := ParamsDigest(map[string]any{"sql": "SELECT ssn FROM customers"})
	if strings.Contains(digest, "ssn") || strings.Contains(digest, "SELECT") {
		t.Fatal("params digest must not contain the raw parameter values")
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest = %q, want sha256: prefix", digest)
	}
}

func TestExportCEF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	c, err := Open(path, "fieldlink-test")
	if err != nil {
		t.Fatal(err)
	}
	c.Append("g1", "fs.read", "allow", "", ParamsDigest(nil))
	c.Append("g1", "fs.list", "deny", "path is not permitted", ParamsDigest(nil))
	c.Close()

	var buf strings.Builder
	if err := ExportCEF(path, &buf); err != nil {
		t.Fatalf("ExportCEF: %v", err)
	}
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 CEF lines, got %d:\n%s", len(lines), out)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "CEF:0|FieldLink|fieldlink|") {
			t.Errorf("line does not look like CEF: %q", l)
		}
	}
	if !strings.Contains(lines[1], "outcome=deny") {
		t.Errorf("expected outcome=deny in %q", lines[1])
	}
}
