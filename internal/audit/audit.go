// Package audit implements the append-only, hash-chained log from
// design.md §8: one JSON object per line, each hashed over its own
// contents plus the previous record's hash, so tampering with any entry
// breaks every hash after it.
//
// Scope note: a Record here captures the policy *decision* (allow/deny,
// with a params digest) — the single choke point every capability already
// passes through in policy.GrantEngine.Authorize. It does not also capture
// post-execution outcome detail (bytes read, row counts) the way
// design.md §8's sample record's "result" field sketches; wiring that in
// would mean touching all four executors' return paths individually.
// Logging every decision, allow and deny, tamper-evidently, is the
// security-relevant property this chain exists for.
package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/gowebpki/jcs"
)

// Record is one audit entry. Hash and PrevHash are computed by Append, not
// set by callers.
type Record struct {
	Seq          int64  `json:"seq"`
	TS           string `json:"ts"`
	AgentID      string `json:"agent_id"`
	GrantID      string `json:"grant_id,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	Capability   string `json:"capability"`
	Decision     string `json:"decision"` // "allow" | "deny"
	Reason       string `json:"reason,omitempty"`
	ParamsDigest string `json:"params_digest"`
	PrevHash     string `json:"prev_hash"`
	Hash         string `json:"hash"`
}

// Chain is an append-only, hash-chained JSONL writer.
type Chain struct {
	mu        sync.Mutex
	f         *os.File
	agentID   string
	sessionID string
	seq       int64
	prevHash  string
}

// Open opens (creating if needed) the audit log at path and resumes the
// chain from its last record, so restarting the process doesn't reset
// seq/prev_hash to zero and silently start a disconnected chain.
func Open(path, agentID string) (*Chain, error) {
	last, err := lastRecord(path)
	if err != nil {
		return nil, fmt.Errorf("audit: reading existing log %s: %w", path, err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}

	sid := make([]byte, 8)
	if _, err := rand.Read(sid); err != nil {
		f.Close()
		return nil, err
	}

	c := &Chain{
		f:         f,
		agentID:   agentID,
		sessionID: hex.EncodeToString(sid),
	}
	if last != nil {
		c.seq = last.Seq
		c.prevHash = last.Hash
	}
	return c, nil
}

func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.f.Close()
}

// Append writes one record for a policy decision. digest should be a
// digest of the call's parameters (never the parameters themselves —
// design.md §8: "An audit log that quietly accumulates plaintext ERP
// queries becomes its own data-protection problem").
func (c *Chain) Append(grantID, capability, decision, reason, paramsDigest string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.seq++
	rec := Record{
		Seq:          c.seq,
		TS:           time.Now().UTC().Format(time.RFC3339Nano),
		AgentID:      c.agentID,
		GrantID:      grantID,
		SessionID:    c.sessionID,
		Capability:   capability,
		Decision:     decision,
		Reason:       reason,
		ParamsDigest: paramsDigest,
		PrevHash:     c.prevHash,
	}

	hash, err := hashRecord(rec)
	if err != nil {
		return err
	}
	rec.Hash = hash

	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := c.f.Write(append(line, '\n')); err != nil {
		return err
	}

	c.prevHash = hash
	return nil
}

// ParamsDigest returns a stable digest for a params map, suitable for
// Append's paramsDigest argument.
func ParamsDigest(params map[string]any) string {
	b, err := json.Marshal(params)
	if err != nil {
		return "sha256:unavailable"
	}
	canonical, err := jcs.Transform(b)
	if err != nil {
		canonical = b
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// hashRecord computes hash = SHA256(jcs(record_without_hash) || prev_hash)
// (design.md §8).
func hashRecord(rec Record) (string, error) {
	rec.Hash = ""
	b, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(b)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(canonical)
	h.Write([]byte(rec.PrevHash))
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
