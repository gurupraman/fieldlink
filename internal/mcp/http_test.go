package server

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gurupraman/fieldlink/internal/policy"
)

// startHTTPServer runs a real fieldlink HTTP server on an ephemeral
// loopback port for the duration of the test.
func startHTTPServer(t *testing.T, opts HTTPOptions) (baseURL string) {
	t.Helper()
	if opts.Bind == "" {
		opts.Bind = "127.0.0.1:0"
	}

	// net/http.Server doesn't expose the resolved ephemeral port directly
	// via ListenAndServe, so bind explicitly with net.Listen and drive the
	// server ourselves via http.Serve — mirroring RunHTTP's shutdown
	// semantics closely enough for a test.
	ln, err := net.Listen("tcp", opts.Bind)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()

	s := New(policy.NewAllowAll(nil), nil)

	handler := gosdk.NewStreamableHTTPHandler(
		func(*http.Request) *gosdk.Server { return s }, &gosdk.StreamableHTTPOptions{},
	)
	var h http.Handler = handler
	if opts.BearerToken != "" {
		h = requireBearerToken(opts.BearerToken, h)
	}
	if len(opts.AllowedOrigins) > 0 {
		cop := http.NewCrossOriginProtection()
		for _, o := range opts.AllowedOrigins {
			if err := cop.AddTrustedOrigin(o); err != nil {
				t.Fatalf("AddTrustedOrigin: %v", err)
			}
		}
		h = cop.Handler(h)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", h)
	srv := &http.Server{Handler: mux}

	go srv.Serve(ln)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})

	return "http://" + addr + "/mcp"
}

func TestHTTPTransport_ToolCallRoundTrip(t *testing.T) {
	baseURL := startHTTPServer(t, HTTPOptions{})

	ctx := context.Background()
	client := gosdk.NewClient(&gosdk.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	cs, err := client.Connect(ctx, &gosdk.StreamableClientTransport{Endpoint: baseURL}, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools.Tools) == 0 {
		t.Fatal("expected at least one tool over HTTP")
	}
}

func TestHTTPTransport_RequiresBearerTokenWhenSet(t *testing.T) {
	baseURL := startHTTPServer(t, HTTPOptions{BearerToken: "secret-token"})

	// No Authorization header at all.
	resp, err := http.Post(baseURL, "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 with no bearer token", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodPost, baseURL, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 with a wrong bearer token", resp2.StatusCode)
	}
}

func TestHTTPTransport_AcceptsCorrectBearerToken(t *testing.T) {
	baseURL := startHTTPServer(t, HTTPOptions{BearerToken: "secret-token"})

	ctx := context.Background()
	client := gosdk.NewClient(&gosdk.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	httpClient := &http.Client{Transport: bearerRoundTripper{token: "secret-token", next: http.DefaultTransport}}
	cs, err := client.Connect(ctx, &gosdk.StreamableClientTransport{Endpoint: baseURL, HTTPClient: httpClient}, nil)
	if err != nil {
		t.Fatalf("client connect with correct token: %v", err)
	}
	defer cs.Close()

	if _, err := cs.ListTools(ctx, nil); err != nil {
		t.Fatalf("ListTools with correct token: %v", err)
	}
}

type bearerRoundTripper struct {
	token string
	next  http.RoundTripper
}

func (b bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(req)
}

func TestRunHTTP_RefusesNonLoopbackWithoutAllowRemote(t *testing.T) {
	err := RunHTTP(context.Background(), New(policy.NewAllowAll(nil), nil), HTTPOptions{
		Bind: "0.0.0.0:18765",
	})
	if err == nil {
		t.Fatal("expected an error binding a non-loopback address without AllowRemote")
	}
}

func TestRunHTTP_RefusesAllowRemoteWithoutToken(t *testing.T) {
	err := RunHTTP(context.Background(), New(policy.NewAllowAll(nil), nil), HTTPOptions{
		Bind:        "0.0.0.0:18766",
		AllowRemote: true,
		// BearerToken deliberately left empty.
	})
	if err == nil {
		t.Fatal("expected an error for --allow-remote with no bearer token configured")
	}
}

func TestRunHTTP_AllowsLoopbackWithoutFlags(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := RunHTTP(ctx, New(policy.NewAllowAll(nil), nil), HTTPOptions{
		Bind: "127.0.0.1:18767",
	})
	if err != nil {
		t.Fatalf("expected a clean shutdown, got: %v", err)
	}
}
