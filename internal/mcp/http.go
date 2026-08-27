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

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
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
	// BearerToken is a static shared-secret token required on every
	// request once AllowRemote is true. Mutually exclusive with OAuth —
	// set at most one.
	BearerToken string
	// OAuth, if set, validates access tokens against an external IdP
	// instead of a static token. Mutually exclusive with BearerToken.
	OAuth *OAuthOptions
	// AllowedOrigins are exact origins allowed to make cross-origin
	// requests (net/http's CrossOriginProtection — exact match only, see
	// config.HTTPConfig.AllowedOrigins).
	AllowedOrigins []string
	// TLS, if both fields are set, terminates HTTPS directly.
	TLSCertFile string
	TLSKeyFile  string
	Logger      *slog.Logger
}

// RunHTTP serves s over Streamable HTTP at /mcp until ctx is cancelled,
// enforcing the hardening design.md §4.1 requires: loopback-only unless
// AllowRemote, an auth mechanism (bearer token or OAuth) whenever
// AllowRemote is set, and origin validation. It never starts a server that
// violates these — validation happens before ListenAndServe, not as a
// runtime check that could be bypassed by a race.
func RunHTTP(ctx context.Context, s *gosdk.Server, opts HTTPOptions) error {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if opts.BearerToken != "" && opts.OAuth != nil {
		return fmt.Errorf("http: bearer_token_env and oauth are mutually exclusive — configure at most one")
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
		if opts.BearerToken == "" && opts.OAuth == nil {
			return fmt.Errorf("http: --allow-remote requires an auth mechanism (bearer_token_env or oauth in config); there is no unauthenticated remote mode")
		}
	}

	handler := gosdk.NewStreamableHTTPHandler(
		func(*http.Request) *gosdk.Server { return s },
		&gosdk.StreamableHTTPOptions{Logger: logger},
	)

	mux := http.NewServeMux()

	var h http.Handler = handler
	switch {
	case opts.OAuth != nil:
		verifier, err := newOIDCVerifier(ctx, *opts.OAuth)
		if err != nil {
			return err
		}
		metadataURL := opts.OAuth.ResourceURL // same host; discovery lives beside /mcp
		if metadataURL != "" {
			mux.Handle("/.well-known/oauth-protected-resource", protectedResourceMetadataHandler(*opts.OAuth))
		}
		h = sdkauth.RequireBearerToken(verifier, &sdkauth.RequireBearerTokenOptions{
			Scopes:              opts.OAuth.RequiredScopes,
			ResourceMetadataURL: metadataURL,
		})(h)
		logger.Info("HTTP transport requires OAuth bearer tokens", "issuer", opts.OAuth.IssuerURL, "audience", opts.OAuth.Audience)
	case opts.BearerToken != "":
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

	mux.Handle("/mcp", h)

	srv := &http.Server{Addr: opts.Bind, Handler: mux}

	useTLS := opts.TLSCertFile != "" && opts.TLSKeyFile != ""
	if opts.AllowRemote && !useTLS {
		logger.Warn("HTTP transport is remote-reachable without TLS configured — bearer tokens and OAuth access tokens will travel in the clear over the network; set server.http.tls in config")
	}

	errCh := make(chan error, 1)
	go func() {
		if useTLS {
			errCh <- srv.ListenAndServeTLS(opts.TLSCertFile, opts.TLSKeyFile)
		} else {
			errCh <- srv.ListenAndServe()
		}
	}()

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
