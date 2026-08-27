package policy

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/gurupraman/fieldlink/internal/grant"
)

// GrantEngine verifies an offline-signed grant (design.md §6) on every
// single call — see grantEngine.load, which re-reads and re-verifies from
// disk each time rather than trusting any in-memory "valid" flag. That is
// the specific bug CLAUDE.md's hard constraint #3 rules out.
type GrantEngine struct {
	agentID    string
	grantPath  string
	trustedKey string
	logger     *slog.Logger

	mu              sync.Mutex
	lastFingerprint string
}

func NewGrantEngine(agentID, grantPath, trustedKeyPath string, logger *slog.Logger) *GrantEngine {
	if logger == nil {
		logger = slog.Default()
	}
	return &GrantEngine{
		agentID:    agentID,
		grantPath:  grantPath,
		trustedKey: trustedKeyPath,
		logger:     logger,
	}
}

// verified is a freshly loaded, signature- and expiry-checked grant.
type verified struct {
	g *grant.Grant
}

// load re-reads the trusted key, grant document, and signature from disk
// and fully re-verifies them. Nothing about the result is cached across
// calls. Any failure is logged with detail for the operator and returned
// as a generic error safe to summarize to the model.
func (e *GrantEngine) load(ctx context.Context) (*verified, error) {
	pub, err := grant.ReadPublicKeyFile(e.trustedKey)
	if err != nil {
		e.logger.Warn("policy: trusted key unreadable", "path", e.trustedKey, "err", err)
		return nil, errDenied("grant is missing or invalid")
	}
	e.noteFingerprint(pub)

	g, canonical, err := parseGrantFile(e.grantPath)
	if err != nil {
		e.logger.Warn("policy: grant unreadable or malformed", "path", e.grantPath, "err", err)
		return nil, errDenied("grant is missing or invalid")
	}
	if err := g.Validate(); err != nil {
		e.logger.Warn("policy: grant failed validation", "err", err)
		return nil, errDenied("grant is missing or invalid")
	}

	sig, err := grant.ReadSignatureFile(sigPathFor(e.grantPath))
	if err != nil {
		e.logger.Warn("policy: signature unreadable", "err", err)
		return nil, errDenied("grant is missing or invalid")
	}
	if !grant.Verify(ed25519.PublicKey(pub), canonical, sig) {
		e.logger.Warn("policy: grant signature verification failed")
		return nil, errDenied("grant is missing or invalid")
	}

	now := time.Now()
	if now.After(g.ExpiresAt) {
		e.logger.Warn("policy: grant expired", "expired_at", g.ExpiresAt)
		return nil, errDenied("grant has expired")
	}
	if g.AgentID != e.agentID {
		e.logger.Warn("policy: grant agent_id mismatch", "grant_agent_id", g.AgentID, "local_agent_id", e.agentID)
		return nil, errDenied("grant is not valid for this installation")
	}

	return &verified{g: g}, nil
}

func (e *GrantEngine) noteFingerprint(pub ed25519.PublicKey) {
	fp := grant.Fingerprint(pub)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastFingerprint == "" {
		e.lastFingerprint = fp
		e.logger.Info("policy: trusted key loaded", "fingerprint", fp)
		return
	}
	if e.lastFingerprint != fp {
		e.logger.Warn("policy: trusted key fingerprint CHANGED — this is not a silent reload", "previous", e.lastFingerprint, "current", fp)
		e.lastFingerprint = fp
	}
}

func (e *GrantEngine) Granted(capability string) bool {
	v, err := e.load(context.Background())
	if err != nil {
		return false
	}
	_, ok := v.g.Find(capability)
	return ok
}

func (e *GrantEngine) Authorize(ctx context.Context, capability string, params map[string]any) Decision {
	v, err := e.load(ctx)
	if err != nil {
		return Decision{Allowed: false, Reason: err.Error()}
	}

	constraints, ok := v.g.Find(capability)
	if !ok {
		return Decision{Allowed: false, Reason: "capability is not permitted"}
	}

	switch capability {
	case "fs.read":
		return authorizeFSRead(constraints, params)
	case "fs.list":
		return authorizeFSList(constraints, params)
	case "device.modbus.read":
		return authorizeModbusRead(constraints, params)
	default:
		// The capability is present in the grant but this build has no
		// constraint logic for it yet — fail closed rather than allow
		// unconditionally.
		return Decision{Allowed: false, Reason: "capability is not permitted"}
	}
}

func authorizeFSRead(constraints map[string]any, params map[string]any) Decision {
	path, _ := params["path"].(string)
	if !pathMatchesAny(constraints["paths"], path) {
		return Decision{Allowed: false, Reason: "path is not permitted"}
	}
	if ceiling, ok := toInt64(constraints["max_bytes"]); ok {
		if requested, ok := toInt64(params["max_bytes"]); ok && requested > ceiling {
			return Decision{Allowed: false, Reason: "max_bytes exceeds what is permitted"}
		}
	}
	return Decision{Allowed: true}
}

func authorizeFSList(constraints map[string]any, params map[string]any) Decision {
	path, _ := params["path"].(string)
	if !pathMatchesAny(constraints["paths"], path) {
		return Decision{Allowed: false, Reason: "path is not permitted"}
	}
	if recurseAllowed, ok := constraints["recursive"].(bool); ok && !recurseAllowed {
		if requested, _ := params["recursive"].(bool); requested {
			return Decision{Allowed: false, Reason: "recursive listing is not permitted"}
		}
	}
	return Decision{Allowed: true}
}

func authorizeModbusRead(constraints map[string]any, params map[string]any) Decision {
	device, _ := params["device"].(string)
	register, _ := params["register"].(string)
	if !stringInList(constraints["devices"], device) {
		return Decision{Allowed: false, Reason: "device is not permitted"}
	}
	if !stringInList(constraints["registers"], register) {
		return Decision{Allowed: false, Reason: "register is not permitted"}
	}
	return Decision{Allowed: true}
}

// stringInList reports whether s is exactly present in list (a []any of
// strings, as decoded from grant YAML). Unlike pathMatchesAny, this is an
// exact-match allow-list, not a glob — device and register names are
// opaque identifiers, not paths.
func stringInList(list any, s string) bool {
	if s == "" {
		return false
	}
	items, ok := list.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if str, ok := item.(string); ok && str == s {
			return true
		}
	}
	return false
}

// pathMatchesAny reports whether path matches any doublestar glob in
// patterns (a []any of strings, as decoded from grant YAML). An empty or
// missing pattern list matches nothing — constraints are allow-lists, never
// implicit wildcards.
func pathMatchesAny(patterns any, path string) bool {
	if path == "" {
		return false
	}
	list, ok := patterns.([]any)
	if !ok {
		return false
	}
	// Constraints are matched after symlink resolution by the executor,
	// which passes the resolved path in; normalize separators defensively.
	clean := filepath.ToSlash(path)
	for _, p := range list {
		pattern, ok := p.(string)
		if !ok {
			continue
		}
		if matched, _ := doublestar.Match(pattern, clean); matched {
			return true
		}
	}
	return false
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	case int64:
		return n, true
	default:
		return 0, false
	}
}
