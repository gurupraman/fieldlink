// Package soap implements the soap.call capability: invoking a named,
// pre-declared SOAP operation against a legacy endpoint. This capability
// is beyond design.md's original six ("no more") — see the package
// comment on config.SOAPEndpoint for why it exists and how it stays
// consistent with the rest of the project's trust model despite that.
//
// There is deliberately no WSDL parsing, no dynamic operation
// construction, and no arbitrary XML from the caller. Each operation is a
// literal envelope template the operator writes into config.yaml; a tool
// call only supplies parameter *values*, which are XML-escaped before
// substitution so a caller can't break out of the declared envelope shape
// and inject arbitrary SOAP body content.
package soap

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gurupraman/fieldlink/internal/config"
	"github.com/gurupraman/fieldlink/internal/policy"
)

const defaultTimeout = 10 * time.Second
const maxResponseBytes = 1 << 20 // 1 MiB

type Executor struct {
	Policy    policy.Engine
	Endpoints map[string]config.SOAPEndpoint

	mu        sync.Mutex
	templates map[string]*template.Template // "endpoint\x00operation" -> parsed template
}

func NewExecutor(eng policy.Engine, endpoints map[string]config.SOAPEndpoint) *Executor {
	return &Executor{
		Policy:    eng,
		Endpoints: endpoints,
		templates: make(map[string]*template.Template),
	}
}

type CallSOAPInput struct {
	Endpoint  string            `json:"endpoint" jsonschema:"configured SOAP endpoint name"`
	Operation string            `json:"operation" jsonschema:"named operation declared for this endpoint in config"`
	Params    map[string]string `json:"params,omitempty" jsonschema:"parameter values substituted into the operation's XML template"`
}

type CallSOAPOutput struct {
	Endpoint   string `json:"endpoint"`
	Operation  string `json:"operation"`
	StatusCode int    `json:"status_code"`
	Body       string `json:"body"` // raw XML response
}

func (e *Executor) CallSOAP(ctx context.Context, _ *gomcp.CallToolRequest, in CallSOAPInput) (*gomcp.CallToolResult, CallSOAPOutput, error) {
	if in.Endpoint == "" || in.Operation == "" {
		return denied("endpoint and operation are required"), CallSOAPOutput{}, nil
	}

	ep, ok := e.Endpoints[in.Endpoint]
	if !ok {
		return denied("endpoint is not configured"), CallSOAPOutput{}, nil
	}
	op, ok := ep.Operations[in.Operation]
	if !ok {
		return denied("operation is not defined for this endpoint"), CallSOAPOutput{}, nil
	}

	decision := e.Policy.Authorize(ctx, "soap.call", map[string]any{
		"endpoint":  in.Endpoint,
		"operation": in.Operation,
	})
	if !decision.Allowed {
		return denied(decision.Reason), CallSOAPOutput{}, nil
	}

	tmpl, err := e.templateFor(in.Endpoint, in.Operation, op.Template)
	if err != nil {
		return denied("operation template is invalid"), CallSOAPOutput{}, nil
	}

	// Every parameter value is XML-escaped before the template sees it,
	// so a value can never close a tag early and inject sibling elements
	// into the declared envelope — the template's structure is fixed;
	// only text content varies.
	escaped := make(map[string]string, len(in.Params))
	for k, v := range in.Params {
		escaped[k] = escapeXMLText(v)
	}

	var body bytes.Buffer
	// missingkey=error: a template referencing {{.X}} with no X supplied
	// fails the call rather than silently sending an empty element —
	// silently-wrong SOAP requests are exactly the "confidently wrong"
	// failure mode design.md warns about elsewhere.
	if err := tmpl.Option("missingkey=error").Execute(&body, escaped); err != nil {
		return denied("params do not satisfy the operation's template"), CallSOAPOutput{}, nil
	}

	timeout := time.Duration(ep.Timeout)
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, ep.URL, bytes.NewReader(body.Bytes()))
	if err != nil {
		return denied("request could not be built"), CallSOAPOutput{}, nil
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	if op.SOAPAction != "" {
		req.Header.Set("SOAPAction", op.SOAPAction)
	}
	if ep.UsernameEnv != "" {
		user := os.Getenv(ep.UsernameEnv)
		pass := os.Getenv(ep.PasswordEnv)
		req.SetBasicAuth(user, pass)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return denied("request failed"), CallSOAPOutput{}, nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return denied("response could not be read"), CallSOAPOutput{}, nil
	}
	truncated := len(respBody) > maxResponseBytes
	if truncated {
		respBody = respBody[:maxResponseBytes]
	}

	out := CallSOAPOutput{
		Endpoint:   in.Endpoint,
		Operation:  in.Operation,
		StatusCode: resp.StatusCode,
		Body:       string(respBody),
	}
	return nil, out, nil
}

// templateFor parses and caches an operation's template, keyed by
// endpoint+operation so a config reload (a fresh Executor) always
// re-parses but a long-running process doesn't re-parse per call.
func (e *Executor) templateFor(endpoint, operation, raw string) (*template.Template, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := endpoint + "\x00" + operation
	if t, ok := e.templates[key]; ok {
		return t, nil
	}
	t, err := template.New(key).Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse template for %s/%s: %w", endpoint, operation, err)
	}
	e.templates[key] = t
	return t, nil
}

// escapeXMLText escapes s for safe insertion as XML character data, using
// encoding/xml's own escaper rather than a hand-rolled replacer — this is
// the security-relevant primitive to get right in this package.
func escapeXMLText(s string) string {
	var buf strings.Builder
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		// EscapeText only fails on a broken io.Writer; a strings.Builder
		// never errors, so this is unreachable, but fail closed rather
		// than emit unescaped content if it ever somehow does.
		return ""
	}
	return buf.String()
}

func denied(reason string) *gomcp.CallToolResult {
	return &gomcp.CallToolResult{
		IsError: true,
		Content: []gomcp.Content{&gomcp.TextContent{Text: "Denied: " + reason}},
	}
}
