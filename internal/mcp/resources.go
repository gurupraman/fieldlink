package server

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gurupraman/fieldlink/internal/config"
	dbexec "github.com/gurupraman/fieldlink/internal/exec/db"
	"github.com/gurupraman/fieldlink/internal/grant"
	"github.com/gurupraman/fieldlink/internal/policy"
)

// registerResources wires the resources described in design.md §4.4.
// Content is filtered to match what the grant actually covers — "a device
// absent from the grant is absent from fieldlink://devices" — using
// eng.GrantedValues, not by re-deriving policy locally.
func registerResources(s *gosdk.Server, eng policy.Engine, cfg *config.Config, dbExec *dbexec.Executor) {
	// fieldlink://grant always exists, even when nothing else is granted,
	// so the model (or an operator) can see *why* nothing is available
	// (design.md §4.4) rather than just getting silence.
	registerGrantResource(s, cfg)

	if eng.Granted("device.modbus.read") {
		registerDeviceResources(s, eng, cfg)
	}
	if eng.Granted("db.query") {
		registerDatasourceResources(s, eng, cfg, dbExec)
	}
}

func jsonContents(uri string, v any) (*gosdk.ReadResourceResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return &gosdk.ReadResourceResult{
		Contents: []*gosdk.ResourceContents{
			{URI: uri, MIMEType: "application/json", Text: string(b)},
		},
	}, nil
}

// --- fieldlink://grant ---

type redactedGrant struct {
	AgentID      string   `json:"agent_id"`
	ExpiresAt    string   `json:"expires_at"`
	Capabilities []string `json:"capabilities"`
}

func registerGrantResource(s *gosdk.Server, cfg *config.Config) {
	s.AddResource(&gosdk.Resource{
		URI:         "fieldlink://grant",
		Name:        "Active grant (redacted)",
		Description: "Capabilities and expiry of the active grant. Constraints, keys, and signatures are not included.",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *gosdk.ReadResourceRequest) (*gosdk.ReadResourceResult, error) {
		g, err := loadGrantDocForDisplay(cfg.Grant.Path)
		if err != nil {
			return jsonContents(req.Params.URI, map[string]string{"status": "no valid grant is active"})
		}
		caps := make([]string, 0, len(g.Capabilities))
		for _, c := range g.Capabilities {
			caps = append(caps, c.Capability)
		}
		sort.Strings(caps)
		return jsonContents(req.Params.URI, redactedGrant{
			AgentID:      g.AgentID,
			ExpiresAt:    g.ExpiresAt.Format("2006-01-02T15:04:05Z"),
			Capabilities: caps,
		})
	})
}

// --- fieldlink://devices, fieldlink://devices/{id}/registers, .../faults ---

type deviceSummary struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
}

func registerDeviceResources(s *gosdk.Server, eng policy.Engine, cfg *config.Config) {
	allowed := eng.GrantedValues("device.modbus.read", "devices")

	s.AddResource(&gosdk.Resource{
		URI:         "fieldlink://devices",
		Name:        "Configured devices",
		Description: "Devices this grant permits reading from.",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *gosdk.ReadResourceRequest) (*gosdk.ReadResourceResult, error) {
		var out []deviceSummary
		for _, name := range sortedKeys(cfg.Devices) {
			if !valueAllowed(allowed, name) {
				continue
			}
			d := cfg.Devices[name]
			out = append(out, deviceSummary{Name: name, Protocol: d.Protocol, Address: d.Address})
		}
		return jsonContents(req.Params.URI, out)
	})

	s.AddResourceTemplate(&gosdk.ResourceTemplate{
		URITemplate: "fieldlink://devices/{id}/registers",
		Name:        "Device register map",
		Description: "Symbolic register names, types, units, and ranges for one device.",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *gosdk.ReadResourceRequest) (*gosdk.ReadResourceResult, error) {
		id, ok := extractID(req.Params.URI, "fieldlink://devices/", "/registers")
		if !ok {
			return nil, gosdk.ResourceNotFoundError(req.Params.URI)
		}
		dev, ok := cfg.Devices[id]
		if !ok || !valueAllowed(allowed, id) {
			return nil, gosdk.ResourceNotFoundError(req.Params.URI)
		}
		registerAllowed := eng.GrantedValues("device.modbus.read", "registers")
		out := map[string]config.Register{}
		for name, reg := range dev.Registers {
			if valueAllowed(registerAllowed, name) {
				out[name] = reg
			}
		}
		return jsonContents(req.Params.URI, out)
	})

	s.AddResourceTemplate(&gosdk.ResourceTemplate{
		URITemplate: "fieldlink://devices/{id}/faults",
		Name:        "Device fault-code table",
		Description: "Fault code -> description lookup for one device.",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *gosdk.ReadResourceRequest) (*gosdk.ReadResourceResult, error) {
		id, ok := extractID(req.Params.URI, "fieldlink://devices/", "/faults")
		if !ok {
			return nil, gosdk.ResourceNotFoundError(req.Params.URI)
		}
		dev, ok := cfg.Devices[id]
		if !ok || !valueAllowed(allowed, id) {
			return nil, gosdk.ResourceNotFoundError(req.Params.URI)
		}
		lookup := firstLookup(dev)
		table, err := cfg.LoadFaultTable(lookup)
		if err != nil {
			return nil, err
		}
		return jsonContents(req.Params.URI, table)
	})
}

// firstLookup returns the first non-empty Lookup filename among a device's
// registers, scanning in a deterministic (sorted) order.
func firstLookup(dev config.Device) string {
	for _, name := range sortedKeys(dev.Registers) {
		if l := dev.Registers[name].Lookup; l != "" {
			return l
		}
	}
	return ""
}

// --- fieldlink://datasources, fieldlink://datasources/{id}/schema ---

type datasourceSummary struct {
	Name   string `json:"name"`
	Driver string `json:"driver"`
}

func registerDatasourceResources(s *gosdk.Server, eng policy.Engine, cfg *config.Config, dbExec *dbexec.Executor) {
	allowed := eng.GrantedValues("db.query", "datasources")

	s.AddResource(&gosdk.Resource{
		URI:         "fieldlink://datasources",
		Name:        "Configured datasources",
		Description: "Datasources this grant permits querying.",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *gosdk.ReadResourceRequest) (*gosdk.ReadResourceResult, error) {
		var out []datasourceSummary
		for _, name := range sortedKeys(cfg.Datasources) {
			if !valueAllowed(allowed, name) {
				continue
			}
			out = append(out, datasourceSummary{Name: name, Driver: cfg.Datasources[name].Driver})
		}
		return jsonContents(req.Params.URI, out)
	})

	s.AddResourceTemplate(&gosdk.ResourceTemplate{
		URITemplate: "fieldlink://datasources/{id}/schema",
		Name:        "Datasource schema",
		Description: "Tables and columns visible to the configured account.",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *gosdk.ReadResourceRequest) (*gosdk.ReadResourceResult, error) {
		id, ok := extractID(req.Params.URI, "fieldlink://datasources/", "/schema")
		if !ok || !valueAllowed(allowed, id) {
			return nil, gosdk.ResourceNotFoundError(req.Params.URI)
		}
		cols, err := dbExec.Schema(ctx, id)
		if err != nil {
			return nil, err
		}
		return jsonContents(req.Params.URI, cols)
	})
}

// --- helpers ---

// valueAllowed reports whether v is permitted: nil means unrestricted
// (AllowAll), otherwise v must be present in the list.
func valueAllowed(allowed []string, v string) bool {
	if allowed == nil {
		return true
	}
	for _, a := range allowed {
		if a == v {
			return true
		}
	}
	return false
}

// extractID pulls {id} out of a concrete URI matching prefix + id + suffix.
func extractID(uri, prefix, suffix string) (string, bool) {
	if !strings.HasPrefix(uri, prefix) || !strings.HasSuffix(uri, suffix) {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(uri, prefix), suffix)
	if id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// loadGrantDocForDisplay reads and shape-parses (not signature-verifies)
// the configured grant file, purely to read redacted metadata for display
// in fieldlink://grant. It reuses internal/grant's parser so display and
// enforcement never drift on what a grant document looks like — but the
// real, signature-verified source of truth for any authorization decision
// is always policy.Engine, never this function.
func loadGrantDocForDisplay(path string) (*grant.Grant, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	g, _, err := grant.ParseYAML(data)
	if err != nil {
		return nil, err
	}
	return g, nil
}
