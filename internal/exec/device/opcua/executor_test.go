package opcua

import (
	"context"
	"testing"
	"time"

	gopcuaserver "github.com/gopcua/opcua/server"
	"github.com/gopcua/opcua/ua"

	"github.com/gurupraman/fieldlink/internal/config"
	"github.com/gurupraman/fieldlink/internal/policy"
)

// startTestServer starts a real, minimal OPC-UA server (no security, no
// auth) with one map-backed namespace containing a couple of tags, and
// returns its endpoint URL, the namespace index the tags were registered
// under (server-assigned, not assumed), and a stop function.
func startTestServer(t *testing.T, port int) (endpointURL string, nsIdx uint16, stop func()) {
	t.Helper()

	opts := []gopcuaserver.Option{
		gopcuaserver.EnableSecurity("None", ua.MessageSecurityModeNone),
		gopcuaserver.EnableAuthMode(ua.UserTokenTypeAnonymous),
		gopcuaserver.EndPoint("127.0.0.1", port),
	}
	srv := gopcuaserver.New(opts...)

	ns := gopcuaserver.NewMapNamespace(srv, "FieldLinkTest")
	ns.Data["BoilerTemp"] = 84.3
	ns.Data["LineSpeed"] = 40

	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.Start(ctx); err != nil {
		cancel()
		t.Fatalf("server.Start: %v", err)
	}

	url := "opc.tcp://127.0.0.1:" + itoa(port)
	return url, ns.ID(), func() {
		cancel()
		srv.Close()
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func grantedOPCUAEngine(t *testing.T, endpointName string, nodePrefixes []string) policy.Engine {
	t.Helper()
	// Reuse AllowAll here would bypass the point of the test — build a
	// real signed grant instead, same as every other executor's tests.
	return grantedEngineFixture(t, endpointName, nodePrefixes)
}

func TestReadOPCUA_RealServer(t *testing.T) {
	url, nsIdx, stop := startTestServer(t, 44840)
	defer stop()

	// Give the listener a beat.
	time.Sleep(50 * time.Millisecond)
	ns := "ns=" + itoa(int(nsIdx)) + ";s="

	eng := grantedOPCUAEngine(t, "scada1", []string{ns + "Boiler", ns + "Line"})
	endpoints := map[string]config.OPCUAEndpoint{
		"scada1": {URL: url, Auth: "anonymous", Timeout: config.Duration(5 * time.Second)},
	}
	exec := NewExecutor(eng, endpoints)

	_, out, err := exec.ReadOPCUA(context.Background(), nil, ReadOPCUAInput{
		Endpoint: "scada1",
		NodeIDs:  []string{ns + "BoilerTemp", ns + "LineSpeed"},
	})
	if err != nil {
		t.Fatalf("ReadOPCUA: %v", err)
	}
	if len(out.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(out.Results))
	}
	if out.Results[0].Status != "good" {
		t.Fatalf("BoilerTemp status = %q", out.Results[0].Status)
	}
	temp, ok := out.Results[0].Value.(float64)
	if !ok || temp != 84.3 {
		t.Fatalf("BoilerTemp value = %v (%T), want 84.3", out.Results[0].Value, out.Results[0].Value)
	}
}

func TestReadOPCUA_DeniesNodeOutsidePrefix(t *testing.T) {
	url, nsIdx, stop := startTestServer(t, 44841)
	defer stop()
	time.Sleep(50 * time.Millisecond)
	ns := "ns=" + itoa(int(nsIdx)) + ";s="

	// Grant only covers Boiler*, not LineSpeed.
	eng := grantedOPCUAEngine(t, "scada1", []string{ns + "Boiler"})
	endpoints := map[string]config.OPCUAEndpoint{
		"scada1": {URL: url, Auth: "anonymous", Timeout: config.Duration(5 * time.Second)},
	}
	exec := NewExecutor(eng, endpoints)

	result, _, err := exec.ReadOPCUA(context.Background(), nil, ReadOPCUAInput{
		Endpoint: "scada1",
		NodeIDs:  []string{ns + "LineSpeed"},
	})
	if err != nil {
		t.Fatalf("ReadOPCUA: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true for a node outside the grant's node_prefixes")
	}
}

func TestReadOPCUA_DeniesUngrantedEndpoint(t *testing.T) {
	url, nsIdx, stop := startTestServer(t, 44842)
	defer stop()
	time.Sleep(50 * time.Millisecond)
	ns := "ns=" + itoa(int(nsIdx)) + ";s="

	eng := grantedOPCUAEngine(t, "some-other-endpoint", []string{ns})
	endpoints := map[string]config.OPCUAEndpoint{
		"scada1": {URL: url, Auth: "anonymous", Timeout: config.Duration(5 * time.Second)},
	}
	exec := NewExecutor(eng, endpoints)

	result, _, err := exec.ReadOPCUA(context.Background(), nil, ReadOPCUAInput{
		Endpoint: "scada1",
		NodeIDs:  []string{ns + "BoilerTemp"},
	})
	if err != nil {
		t.Fatalf("ReadOPCUA: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true for an endpoint not present in the grant")
	}
}

// objectsFolder is the standard OPC-UA "Objects" node under a given
// namespace — the only node this test server's MapNamespace actually
// returns children for (see gopcua/opcua/server's namespace_map.go).
func objectsFolder(nsIdx uint16) string {
	return "ns=" + itoa(int(nsIdx)) + ";i=85"
}

func TestBrowseOPCUA_RealServer(t *testing.T) {
	url, nsIdx, stop := startTestServer(t, 44843)
	defer stop()
	time.Sleep(50 * time.Millisecond)
	objFolder := objectsFolder(nsIdx)

	// A namespace-level prefix covers both the Objects folder node id
	// (ns=X;i=85) and the leaf variable node ids (ns=X;s=...) — see the
	// package doc comment on BrowseOPCUA for why a leaf-only prefix like
	// "ns=X;s=Boiler" would never be able to browse at all.
	eng := grantedOPCUAEngine(t, "scada1", []string{"ns=" + itoa(int(nsIdx)) + ";"})
	endpoints := map[string]config.OPCUAEndpoint{
		"scada1": {URL: url, Auth: "anonymous", Timeout: config.Duration(5 * time.Second)},
	}
	exec := NewExecutor(eng, endpoints)

	_, out, err := exec.BrowseOPCUA(context.Background(), nil, BrowseOPCUAInput{
		Endpoint: "scada1",
		NodeID:   objFolder,
	})
	if err != nil {
		t.Fatalf("BrowseOPCUA: %v", err)
	}
	names := map[string]bool{}
	for _, c := range out.Children {
		names[c.BrowseName] = true
		if c.NodeClass == "" {
			t.Errorf("child %s has empty node_class", c.NodeID)
		}
	}
	if !names["BoilerTemp"] || !names["LineSpeed"] {
		t.Fatalf("expected BoilerTemp and LineSpeed among children, got %v", out.Children)
	}
}

func TestBrowseOPCUA_FiltersChildrenOutsidePrefix(t *testing.T) {
	url, nsIdx, stop := startTestServer(t, 44844)
	defer stop()
	time.Sleep(50 * time.Millisecond)
	objFolder := objectsFolder(nsIdx)
	ns := "ns=" + itoa(int(nsIdx)) + ";s="

	// Authorizes browsing the Objects folder (exact match) but only
	// permits Boiler*-prefixed children — LineSpeed must be filtered out
	// of the results, not just inaccessible to a direct read.
	eng := grantedOPCUAEngine(t, "scada1", []string{objFolder, ns + "Boiler"})
	endpoints := map[string]config.OPCUAEndpoint{
		"scada1": {URL: url, Auth: "anonymous", Timeout: config.Duration(5 * time.Second)},
	}
	exec := NewExecutor(eng, endpoints)

	_, out, err := exec.BrowseOPCUA(context.Background(), nil, BrowseOPCUAInput{
		Endpoint: "scada1",
		NodeID:   objFolder,
	})
	if err != nil {
		t.Fatalf("BrowseOPCUA: %v", err)
	}
	names := map[string]bool{}
	for _, c := range out.Children {
		names[c.BrowseName] = true
	}
	if !names["BoilerTemp"] {
		t.Fatalf("expected BoilerTemp in filtered children, got %v", out.Children)
	}
	if names["LineSpeed"] {
		t.Fatalf("LineSpeed should have been filtered out (outside node_prefixes), got %v", out.Children)
	}
}

func TestBrowseOPCUA_DeniesStartNodeOutsidePrefix(t *testing.T) {
	url, nsIdx, stop := startTestServer(t, 44845)
	defer stop()
	time.Sleep(50 * time.Millisecond)
	ns := "ns=" + itoa(int(nsIdx)) + ";s="

	// Only a leaf prefix granted — no prefix covers the Objects folder
	// node id itself, so the browse must be denied outright, matching
	// the documented "leaf-only prefixes can never browse" behavior.
	eng := grantedOPCUAEngine(t, "scada1", []string{ns + "Boiler"})
	endpoints := map[string]config.OPCUAEndpoint{
		"scada1": {URL: url, Auth: "anonymous", Timeout: config.Duration(5 * time.Second)},
	}
	exec := NewExecutor(eng, endpoints)

	result, _, err := exec.BrowseOPCUA(context.Background(), nil, BrowseOPCUAInput{
		Endpoint: "scada1",
		NodeID:   objectsFolder(nsIdx),
	})
	if err != nil {
		t.Fatalf("BrowseOPCUA: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true when no granted prefix covers the browse start node")
	}
}

func TestBrowseOPCUA_DeniesUngrantedEndpoint(t *testing.T) {
	url, nsIdx, stop := startTestServer(t, 44846)
	defer stop()
	time.Sleep(50 * time.Millisecond)

	eng := grantedOPCUAEngine(t, "some-other-endpoint", []string{"ns=" + itoa(int(nsIdx)) + ";"})
	endpoints := map[string]config.OPCUAEndpoint{
		"scada1": {URL: url, Auth: "anonymous", Timeout: config.Duration(5 * time.Second)},
	}
	exec := NewExecutor(eng, endpoints)

	result, _, err := exec.BrowseOPCUA(context.Background(), nil, BrowseOPCUAInput{
		Endpoint: "scada1",
		NodeID:   objectsFolder(nsIdx),
	})
	if err != nil {
		t.Fatalf("BrowseOPCUA: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true for an endpoint not present in the grant")
	}
}
