package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gurupraman/fieldlink/internal/config"
	"github.com/gurupraman/fieldlink/internal/grant"
	"github.com/gurupraman/fieldlink/internal/policy"
)

// connectInMemory starts s and returns a connected client session, closed
// automatically at test cleanup.
func connectInMemory(t *testing.T, s *gosdk.Server) *gosdk.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverTransport, clientTransport := gosdk.NewInMemoryTransports()

	serverSession, err := s.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { serverSession.Close() })

	client := gosdk.NewClient(&gosdk.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { clientSession.Close() })
	return clientSession
}

// TestResourcesAndPrompts builds a real signed grant covering
// device.modbus.read for exactly one device and one of its two registers,
// a real fault table file, and drives the actual MCP resources/list,
// resources/read, prompts/list and prompts/get methods — proving resource
// content is filtered to match the grant, matching design.md §4.4's claim
// that resources are "filtered by the grant exactly as tools are."
func TestResourcesAndPrompts(t *testing.T) {
	dir := t.TempDir()

	faultsPath := filepath.Join(dir, "faults.yaml")
	if err := os.WriteFile(faultsPath, []byte("0: \"No fault\"\n12: \"High temperature\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		AgentID:   "fieldlink-test",
		ConfigDir: dir,
		Devices: map[string]config.Device{
			"line2-plc": {
				Protocol: "modbus-tcp",
				Address:  "127.0.0.1:5020",
				Registers: map[string]config.Register{
					"boiler_temp": {FC: 3, Address: 20, Type: "float32", Unit: "degC", Lookup: ""},
					"fault_code":  {FC: 3, Address: 40, Type: "uint16", Lookup: "faults.yaml"},
				},
			},
		},
	}

	// Grant covers line2-plc, but only the fault_code register — not
	// boiler_temp — so the registers resource content must reflect that.
	grantYAML := `
version: 1
grant_id: 01J9Z8Q7K3M4N5P6R7S8T9V0W1
agent_id: fieldlink-test
issued_at: ` + time.Now().Add(-1*time.Hour).UTC().Format(time.RFC3339) + `
expires_at: ` + time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339) + `
issuer: security@example.com
capabilities:
  - capability: device.modbus.read
    constraints:
      devices: ["line2-plc"]
      registers: ["fault_code"]
`
	pub, priv, err := grant.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	g, canonical, err := grant.ParseYAML([]byte(grantYAML))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	sig := grant.Sign(priv, canonical)
	grantPath := filepath.Join(dir, "grant.yaml")
	if err := os.WriteFile(grantPath, []byte(grantYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := grant.WriteSignatureFile(grantPath+".sig", sig); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "trusted.pub")
	if err := grant.WritePublicKeyFile(pubPath, pub); err != nil {
		t.Fatal(err)
	}
	cfg.Grant = config.GrantConfig{Path: grantPath, TrustedKey: pubPath}

	eng := policy.NewGrantEngine("fieldlink-test", grantPath, pubPath, nil)
	s := New(eng, cfg)
	cs := connectInMemory(t, s)
	ctx := context.Background()

	// fieldlink://grant
	grantRes, err := cs.ReadResource(ctx, &gosdk.ReadResourceParams{URI: "fieldlink://grant"})
	if err != nil {
		t.Fatalf("ReadResource(fieldlink://grant): %v", err)
	}
	var redacted map[string]any
	mustUnmarshalResource(t, grantRes, &redacted)
	if redacted["agent_id"] != "fieldlink-test" {
		t.Errorf("grant resource agent_id = %v", redacted["agent_id"])
	}
	caps, _ := redacted["capabilities"].([]any)
	if len(caps) != 1 || caps[0] != "device.modbus.read" {
		t.Errorf("grant resource capabilities = %v", redacted["capabilities"])
	}

	// fieldlink://devices
	devicesRes, err := cs.ReadResource(ctx, &gosdk.ReadResourceParams{URI: "fieldlink://devices"})
	if err != nil {
		t.Fatalf("ReadResource(fieldlink://devices): %v", err)
	}
	var devices []map[string]any
	mustUnmarshalResource(t, devicesRes, &devices)
	if len(devices) != 1 || devices[0]["name"] != "line2-plc" {
		t.Fatalf("devices resource = %v", devices)
	}

	// fieldlink://devices/line2-plc/registers — must contain fault_code
	// (granted) but NOT boiler_temp (not granted).
	regRes, err := cs.ReadResource(ctx, &gosdk.ReadResourceParams{URI: "fieldlink://devices/line2-plc/registers"})
	if err != nil {
		t.Fatalf("ReadResource(registers): %v", err)
	}
	var registers map[string]any
	mustUnmarshalResource(t, regRes, &registers)
	if _, ok := registers["fault_code"]; !ok {
		t.Error("expected fault_code in the filtered register map")
	}
	if _, ok := registers["boiler_temp"]; ok {
		t.Error("boiler_temp should be filtered out: it is not in the grant's registers[]")
	}

	// fieldlink://devices/line2-plc/faults
	faultsRes, err := cs.ReadResource(ctx, &gosdk.ReadResourceParams{URI: "fieldlink://devices/line2-plc/faults"})
	if err != nil {
		t.Fatalf("ReadResource(faults): %v", err)
	}
	var faults map[string]string
	mustUnmarshalResource(t, faultsRes, &faults)
	if faults["12"] != "High temperature" {
		t.Errorf("faults[12] = %q, want %q", faults["12"], "High temperature")
	}

	// prompts/list and prompts/get
	prompts, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	if len(prompts.Prompts) != 3 {
		t.Fatalf("expected 3 prompts, got %d", len(prompts.Prompts))
	}

	got, err := cs.GetPrompt(ctx, &gosdk.GetPromptParams{
		Name:      "diagnose_device",
		Arguments: map[string]string{"device": "line2-plc"},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	text := got.Messages[0].Content.(*gosdk.TextContent).Text
	if !strings.Contains(text, "line2-plc") {
		t.Errorf("prompt text does not mention the device: %q", text)
	}
}

func mustUnmarshalResource(t *testing.T, res *gosdk.ReadResourceResult, out any) {
	t.Helper()
	if len(res.Contents) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(res.Contents))
	}
	if err := json.Unmarshal([]byte(res.Contents[0].Text), out); err != nil {
		t.Fatalf("unmarshal resource content: %v", err)
	}
}
