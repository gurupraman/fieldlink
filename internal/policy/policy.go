// Package policy is the trust boundary described in docs/design.md §6.
//
// Week 1 ships only [AllowAll], a stub that authorises every call. It exists
// so the MCP and executor layers are written against the real interface from
// the start — Week 2 replaces AllowAll with an engine that verifies an
// Ed25519-signed grant on every call, without either caller changing.
package policy

import (
	"context"
	"log/slog"
)

// Decision is the result of a policy check.
type Decision struct {
	Allowed bool
	// Reason is safe to return to the model: it must never echo host paths
	// or reveal what the grant would otherwise have allowed (design.md §4.3).
	Reason string
}

// Engine is the trust boundary. It is consulted before every capability
// execution and must never cache a prior "allowed" result — see design.md
// §6.4, "a cached grant-is-valid boolean is precisely the bug this design
// exists to prevent."
type Engine interface {
	// Authorize decides whether capability may run with the given params.
	// capability is a dotted id such as "fs.read". params are
	// capability-specific arguments used for constraint matching (paths,
	// registers, CIDRs, ...) once a real grant is enforced.
	Authorize(ctx context.Context, capability string, params map[string]any) Decision

	// Granted reports whether capability should be advertised in
	// tools/list and resources/list at all. A capability absent from the
	// grant must never appear there (design.md §4.3).
	Granted(capability string) bool
}

// AllowAll is a policy engine that authorises every call unconditionally.
//
// TODO(week-2): THIS IS NOT A SECURITY BOUNDARY. Replace with the real
// grant-verifying engine (Ed25519 signature, expiry, agent binding,
// per-call constraint matching) before this binary is ever pointed at a
// live device, database, or filesystem outside a throwaway demo. AllowAll
// must never be the default in a release build.
type AllowAll struct {
	logger *slog.Logger
}

// NewAllowAll constructs the stub engine and logs a loud, repeated warning
// so the gap is impossible to miss in an operator's log stream.
func NewAllowAll(logger *slog.Logger) *AllowAll {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("POLICY ENGINE IS A STUB — every capability is allowed unconditionally; no grant is verified; this build must not be used against real devices, databases, or filesystems")
	return &AllowAll{logger: logger}
}

func (a *AllowAll) Authorize(_ context.Context, capability string, _ map[string]any) Decision {
	a.logger.Warn("policy: allowed by AllowAll stub, not a real grant check", "capability", capability)
	return Decision{Allowed: true, Reason: "AllowAll stub (Week 2 replaces this)"}
}

func (a *AllowAll) Granted(string) bool {
	return true
}
