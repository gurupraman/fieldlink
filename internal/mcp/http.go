package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// HTTPOptions configures the Streamable HTTP transport (design.md §4.1).
type HTTPOptions struct {
	// Bind is host:port to listen on.
	Bind string
	// AllowRemote must be true for Bind to resolve to anything other than
	// a loopback address. Config alone cannot set this — it's CLI-only —
	// so a leaked or misconfigured config file can't silently turn into a
	// network-exposed server.
	AllowRemote bool
	// BearerToken is required on every request once AllowRemote is true
	// (design.md: "no unauthenticated remote mode"). Ignored (no auth
	// required) when AllowRemote is false.
	BearerToken string
	// AllowedOrigins are exact origins allowed to make cross-origin
	// requests (net/http's CrossOriginProtection — exact match only, see
	// config.HTTPConfig.AllowedOrigins).
	AllowedOrigins []string
	Logger         *slog.Logger
}

// RunHTTP serves s over Streamable HTTP at /mcp until ctx is cancelled,
// enforcing the hardening design.md §4.1 requires: loopback-only unless
// AllowRemote, a bearer token whenever AllowRemote is set, and origin
// validation. It never starts a server that violates these — validation
// happens before ListenAndServe, not as a runtime check that could be
// bypassed by a race.
func RunHTTP(ctx context.Context, s *gosdk.Server, opts HTTPOptions) error {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	host, _, err := net.SplitHostPort(opts.Bind)
	if err != nil {
		return fmt.Errorf("http: invalid bind address %q: %w", opts.Bind, err)
	}
	if !isLoopbackHost(host) && !opts.AllowRemote {
		return fmt.Errorf("http: refusing to bind non-loopback address %q without --allow-remote", opts.Bind)
	}
	if opts.AllowRemote {
		logger.Warn("HTTP transport is remote-reachable — this widens network exposure beyond this host", "bind", opts.Bind)
		if opts.BearerToken == "" {
			return fmt.Errorf("http: --allow-remote requires a bearer token (server.http.bearer_token_env in config); there is no unauthenticated remote mode")
		}
	}

	handler := gosdk.NewStreamableHTTPHandler(
		func(*http.Request) *gosdk.Server { return s },
		&gosdk.StreamableHTTPOptions{Logger: logger},
	)

	var h http.Handler = handler
	if opts.BearerToken != "" {
		h = requireBearerToken(opts.BearerToken, h)
	}
	if len(opts.AllowedOrigins) > 0 {
		cop := http.NewCrossOriginProtection()
		for _, o := range opts.AllowedOrigins {
			if err := cop.AddTrustedOrigin(o); err != nil {
				return fmt.Errorf("http: invalid allowed_origins entry %q: %w", o, err)
			}
		}
		h = cop.Handler(h)
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp", h)

	srv := &http.Server{Addr: opts.Bind, Handler: mux}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func requireBearerToken(token string, next http.Handler) http.Handler {
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
