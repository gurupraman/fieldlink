package httpx

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gurupraman/fieldlink/internal/policy"
)

const maxBodyBytes = 1 << 20 // 1 MiB

// Executor implements call_internal_http. GET and HEAD only; redirects are
// never followed automatically (a deliberate simplification vs. design.md's
// "re-check IP after each redirect" — not following redirects at all is a
// strict superset of that safety property, and avoids the well-known class
// of SSRF bugs that live in partial redirect-chasing logic). The 3xx
// response, including its Location header, is simply returned to the
// caller to act on if it chooses.
type Executor struct {
	Policy policy.Engine
}

type CallInternalHTTPInput struct {
	URL     string            `json:"url" jsonschema:"the URL to request"`
	Method  string            `json:"method,omitempty" jsonschema:"GET or HEAD; defaults to GET"`
	Headers map[string]string `json:"headers,omitempty" jsonschema:"optional request headers"`
}

type CallInternalHTTPOutput struct {
	URL       string              `json:"url"`
	Status    int                 `json:"status"`
	Headers   map[string][]string `json:"headers"`
	Body      string              `json:"body,omitempty"`
	Truncated bool                `json:"truncated"`
}

func (e *Executor) CallInternalHTTP(ctx context.Context, _ *gomcp.CallToolRequest, in CallInternalHTTPInput) (*gomcp.CallToolResult, CallInternalHTTPOutput, error) {
	method := strings.ToUpper(in.Method)
	if method == "" {
		method = "GET"
	}
	if method != "GET" && method != "HEAD" {
		return denied("method is not permitted"), CallInternalHTTPOutput{}, nil
	}

	u, err := url.Parse(in.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return denied("url is not valid"), CallInternalHTTPOutput{}, nil
	}
	host := u.Hostname()
	if host == "" {
		return denied("url is not valid"), CallInternalHTTPOutput{}, nil
	}

	ips, err := resolve(host)
	if err != nil {
		return denied("host could not be resolved"), CallInternalHTTPOutput{}, nil
	}

	// The metadata block is absolute — it is checked before, and
	// independent of, anything the grant permits (design.md §5.1).
	for _, ip := range ips {
		if isMetadataBlocked(ip) {
			return denied("this address is not permitted"), CallInternalHTTPOutput{}, nil
		}
	}

	targetIP := ips[0]
	decision := e.Policy.Authorize(ctx, "http.request", map[string]any{
		"resolved_ip": targetIP.String(),
		"method":      method,
	})
	if !decision.Allowed {
		return denied(decision.Reason), CallInternalHTTPOutput{}, nil
	}

	client := pinnedClient(targetIP, u.Port(), host)

	req, err := http.NewRequestWithContext(ctx, method, in.URL, nil)
	if err != nil {
		return denied("request could not be built"), CallInternalHTTPOutput{}, nil
	}
	for k, v := range in.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return denied("request failed"), CallInternalHTTPOutput{}, nil
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return denied("response could not be read"), CallInternalHTTPOutput{}, nil
	}
	truncated := len(body) > maxBodyBytes
	if truncated {
		body = body[:maxBodyBytes]
	}

	out := CallInternalHTTPOutput{
		URL:       in.URL,
		Status:    resp.StatusCode,
		Headers:   map[string][]string(resp.Header),
		Body:      string(body),
		Truncated: truncated,
	}
	return nil, out, nil
}

// pinnedClient dials exactly ip:port, ignoring whatever hostname the
// request URL contains at connect time — that's what prevents a
// DNS-rebinding attack from swapping the address out between the CIDR
// check above and the actual connection. sniHost keeps TLS certificate
// verification working against the original hostname.
func pinnedClient(ip net.IP, port, sniHost string) *http.Client {
	if port == "" {
		port = "80"
	}
	dialAddr := net.JoinHostPort(ip.String(), port)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, dialAddr)
		},
		TLSClientConfig: &tls.Config{ServerName: sniHost},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func denied(reason string) *gomcp.CallToolResult {
	return &gomcp.CallToolResult{
		IsError: true,
		Content: []gomcp.Content{&gomcp.TextContent{Text: "Denied: " + reason}},
	}
}
