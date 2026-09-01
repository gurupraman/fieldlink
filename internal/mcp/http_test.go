package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
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

// TestRunHTTP_TLS drives RunHTTP with a real, freshly generated self-signed
// certificate and connects with a real HTTPS client that trusts it —
// proving ListenAndServeTLS is actually wired up, not just that the flag
// exists.
func TestRunHTTP_TLS(t *testing.T) {
	certPEM, keyPEM, certDER := generateSelfSignedCert(t)
	certFile := writeTempFile(t, "cert.pem", certPEM)
	keyFile := writeTempFile(t, "key.pem", keyPEM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bind := "127.0.0.1:18768"
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunHTTP(ctx, New(policy.NewAllowAll(nil), nil), HTTPOptions{
			Bind:        bind,
			TLSCertFile: certFile,
			TLSKeyFile:  keyFile,
		})
	}()
	time.Sleep(100 * time.Millisecond)

	pool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(cert)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}

	resp, err := client.Get("https://" + bind + "/mcp")
	if err != nil {
		t.Fatalf("HTTPS GET failed — TLS is not actually serving: %v", err)
	}
	// GET /mcp is the spec's standalone-SSE-stream request, so the
	// response can be a long-lived stream, not a small bounded body —
	// closing it without draining first forces an abrupt connection
	// reset rather than a clean close. On this project that difference
	// only showed up as a real, non-hypothetical failure on Windows CI
	// (srv.Shutdown below blocked past its 5s timeout waiting for the
	// connection to close), never locally — drain before Close()
	// unconditionally so this class of bug can't recur.
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("RunHTTP: %v", err)
	}
}

func generateSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte, certDER []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, der
}

func writeTempFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
