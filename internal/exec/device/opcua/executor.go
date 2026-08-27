// Package opcua implements the device.opcua.read capability (design.md
// §5) as the read_opcua MCP tool. Unlike Modbus, OPC-UA node IDs are
// already self-describing (ns=2;s=Boiler.Temperature) and Browse is
// supported, so there's no register-map layer — the model reads node IDs
// directly, and the grant constrains which ones by prefix.
package opcua

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	gopcua "github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gurupraman/fieldlink/internal/config"
	"github.com/gurupraman/fieldlink/internal/policy"
)

type Executor struct {
	Policy    policy.Engine
	Endpoints map[string]config.OPCUAEndpoint

	mu    sync.Mutex
	conns map[string]*gopcua.Client
}

func NewExecutor(eng policy.Engine, endpoints map[string]config.OPCUAEndpoint) *Executor {
	return &Executor{
		Policy:    eng,
		Endpoints: endpoints,
		conns:     make(map[string]*gopcua.Client),
	}
}

type ReadOPCUAInput struct {
	Endpoint string   `json:"endpoint" jsonschema:"configured OPC-UA endpoint name"`
	NodeIDs  []string `json:"node_ids" jsonschema:"OPC-UA node IDs to read, e.g. ns=2;s=Boiler.Temperature"`
}

type OPCUANodeResult struct {
	NodeID          string `json:"node_id"`
	Value           any    `json:"value,omitempty"`
	Status          string `json:"status"` // "good" or a status code description
	SourceTimestamp string `json:"source_timestamp,omitempty"`
}

type ReadOPCUAOutput struct {
	Endpoint string            `json:"endpoint"`
	Results  []OPCUANodeResult `json:"results"`
}

func (e *Executor) ReadOPCUA(ctx context.Context, _ *gomcp.CallToolRequest, in ReadOPCUAInput) (*gomcp.CallToolResult, ReadOPCUAOutput, error) {
	if in.Endpoint == "" || len(in.NodeIDs) == 0 {
		return denied("endpoint and node_ids are required"), ReadOPCUAOutput{}, nil
	}

	ep, ok := e.Endpoints[in.Endpoint]
	if !ok {
		return denied("endpoint is not configured"), ReadOPCUAOutput{}, nil
	}

	decision := e.Policy.Authorize(ctx, "device.opcua.read", map[string]any{
		"endpoint": in.Endpoint,
		"node_ids": in.NodeIDs,
	})
	if !decision.Allowed {
		return denied(decision.Reason), ReadOPCUAOutput{}, nil
	}

	ids := make([]*ua.NodeID, len(in.NodeIDs))
	for i, s := range in.NodeIDs {
		id, err := ua.ParseNodeID(s)
		if err != nil {
			return denied("a node id is not valid"), ReadOPCUAOutput{}, nil
		}
		ids[i] = id
	}

	client, err := e.clientFor(ctx, in.Endpoint, ep)
	if err != nil {
		return denied("could not connect to endpoint"), ReadOPCUAOutput{}, nil
	}

	reqIDs := make([]*ua.ReadValueID, len(ids))
	for i, id := range ids {
		reqIDs[i] = &ua.ReadValueID{NodeID: id}
	}
	resp, err := client.Read(ctx, &ua.ReadRequest{
		NodesToRead:        reqIDs,
		TimestampsToReturn: ua.TimestampsToReturnSource,
	})
	if err != nil {
		e.resetConn(in.Endpoint)
		return denied("read failed"), ReadOPCUAOutput{}, nil
	}

	results := make([]OPCUANodeResult, len(in.NodeIDs))
	for i, dv := range resp.Results {
		r := OPCUANodeResult{NodeID: in.NodeIDs[i]}
		if dv.Status == ua.StatusOK {
			r.Status = "good"
			if dv.Value != nil {
				r.Value = dv.Value.Value()
			}
			if !dv.SourceTimestamp.IsZero() {
				r.SourceTimestamp = dv.SourceTimestamp.UTC().Format(time.RFC3339)
			}
		} else {
			r.Status = dv.Status.Error()
		}
		results[i] = r
	}

	return nil, ReadOPCUAOutput{Endpoint: in.Endpoint, Results: results}, nil
}

func (e *Executor) clientFor(ctx context.Context, name string, ep config.OPCUAEndpoint) (*gopcua.Client, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if c, ok := e.conns[name]; ok {
		return c, nil
	}

	opts := []gopcua.Option{gopcua.SecurityMode(ua.MessageSecurityModeNone)}
	switch ep.Auth {
	case "", "anonymous":
		opts = append(opts, gopcua.AuthAnonymous())
	case "username":
		user := os.Getenv(ep.UsernameEnv)
		pass := os.Getenv(ep.PasswordEnv)
		if user == "" {
			return nil, fmt.Errorf("environment variable %s is not set", ep.UsernameEnv)
		}
		opts = append(opts, gopcua.AuthUsername(user, pass))
	default:
		return nil, fmt.Errorf("unknown auth mode %q", ep.Auth)
	}

	c, err := gopcua.NewClient(ep.URL, opts...)
	if err != nil {
		return nil, err
	}
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}

	e.conns[name] = c
	return c, nil
}

func (e *Executor) resetConn(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.conns[name]; ok {
		c.Close(context.Background())
		delete(e.conns, name)
	}
}

func denied(reason string) *gomcp.CallToolResult {
	return &gomcp.CallToolResult{
		IsError: true,
		Content: []gomcp.Content{&gomcp.TextContent{Text: "Denied: " + reason}},
	}
}
