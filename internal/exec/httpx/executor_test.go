package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gurupraman/fieldlink/internal/grant"
	"github.com/gurupraman/fieldlink/internal/policy"
)

// grantedEngine signs a grant covering http.request for the given CIDR and
// methods, and returns a real GrantEngine — the same kind runtime code
// uses, not a test double.
func grantedEngine(t *testing.T, cidr string, methods []string) policy.Engine {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := grant.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	methodsYAML := ""
	for _, m := range methods {
		methodsYAML += `"` + m + `", `
	}

	yaml := `
version: 1
grant_id: 01J9Z8Q7K3M4N5P6R7S8T9V0W1
agent_id: fieldlink-test
issued_at: ` + time.Now().Add(-1*time.Hour).UTC().Format(time.RFC3339) + `
expires_at: ` + time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339) + `
issuer: security@example.com
capabilities:
  - capability: http.request
    constraints:
      cidrs: ["` + cidr + `"]
      methods: [` + methodsYAML + `]
`
	g, canonical, err := grant.ParseYAML([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	sig := grant.Sign(priv, canonical)

	grantPath := dir + "/grant.yaml"
	if err := os.WriteFile(grantPath, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := grant.WriteSignatureFile(grantPath+".sig", sig); err != nil {
		t.Fatal(err)
	}
	pubPath := dir + "/trusted.pub"
	if err := grant.WritePublicKeyFile(pubPath, pub); err != nil {
		t.Fatal(err)
	}

	return policy.NewGrantEngine("fieldlink-test", grantPath, pubPath, nil)
}

func TestCallInternalHTTP_AllowedRequestSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "yes")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from internal service"))
	}))
	defer srv.Close()

	eng := grantedEngine(t, "127.0.0.1/32", []string{"GET"})
	exec := &Executor{Policy: eng}

	_, out, err := exec.CallInternalHTTP(context.Background(), nil, CallInternalHTTPInput{URL: srv.URL})
	if err != nil {
		t.Fatalf("CallInternalHTTP: %v", err)
	}
	if out.Status != 200 {
		t.Fatalf("status = %d, want 200", out.Status)
	}
	if out.Body != "hello from internal service" {
		t.Fatalf("body = %q", out.Body)
	}
	if out.Headers["X-Test"] == nil {
		t.Fatalf("missing X-Test header in %v", out.Headers)
	}
}

func TestCallInternalHTTP_DeniesOutsideCIDR(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Grant only covers an unrelated CIDR, not 127.0.0.1.
	eng := grantedEngine(t, "10.0.0.0/8", []string{"GET"})
	exec := &Executor{Policy: eng}

	result, _, err := exec.CallInternalHTTP(context.Background(), nil, CallInternalHTTPInput{URL: srv.URL})
	if err != nil {
		t.Fatalf("CallInternalHTTP: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true for a host outside the grant's CIDR")
	}
}

func TestCallInternalHTTP_DeniesDisallowedMethod(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	eng := grantedEngine(t, "127.0.0.1/32", []string{"HEAD"}) // GET not granted
	exec := &Executor{Policy: eng}

	result, _, err := exec.CallInternalHTTP(context.Background(), nil, CallInternalHTTPInput{URL: srv.URL, Method: "GET"})
	if err != nil {
		t.Fatalf("CallInternalHTTP: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true for a method outside the grant")
	}
}

func TestCallInternalHTTP_RejectsUnsupportedMethod(t *testing.T) {
	eng := grantedEngine(t, "127.0.0.1/32", []string{"GET", "HEAD", "POST"})
	exec := &Executor{Policy: eng}

	result, _, err := exec.CallInternalHTTP(context.Background(), nil, CallInternalHTTPInput{URL: "http://127.0.0.1:1/x", Method: "POST"})
	if err != nil {
		t.Fatalf("CallInternalHTTP: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true: only GET/HEAD are ever supported, regardless of the grant")
	}
}

func TestCallInternalHTTP_DoesNotFollowRedirects(t *testing.T) {
	var target string
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	})
	mux.HandleFunc("/landed", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should not be reached automatically"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	target = srv.URL + "/landed"

	eng := grantedEngine(t, "127.0.0.1/32", []string{"GET"})
	exec := &Executor{Policy: eng}

	_, out, err := exec.CallInternalHTTP(context.Background(), nil, CallInternalHTTPInput{URL: srv.URL + "/start"})
	if err != nil {
		t.Fatalf("CallInternalHTTP: %v", err)
	}
	if out.Status != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirect not followed)", out.Status)
	}
	if out.Headers["Location"] == nil {
		t.Fatal("expected Location header to be surfaced")
	}
}
