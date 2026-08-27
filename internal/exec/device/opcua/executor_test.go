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
