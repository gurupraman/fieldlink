package opcua

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gurupraman/fieldlink/internal/grant"
	"github.com/gurupraman/fieldlink/internal/policy"
)

// grantedEngineFixture signs a real grant covering device.opcua.read for
// one endpoint and a set of node ID prefixes, and returns a real
// GrantEngine — the same kind runtime code uses.
func grantedEngineFixture(t *testing.T, endpointName string, nodePrefixes []string) policy.Engine {
	t.Helper()
	dir := t.TempDir()

	prefixesYAML := ""
	for _, p := range nodePrefixes {
		prefixesYAML += `"` + p + `", `
	}

	yaml := `
version: 1
grant_id: 01J9Z8Q7K3M4N5P6R7S8T9V0W1
agent_id: fieldlink-test
issued_at: ` + time.Now().Add(-1*time.Hour).UTC().Format(time.RFC3339) + `
expires_at: ` + time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339) + `
issuer: security@example.com
capabilities:
  - capability: device.opcua.read
    constraints:
      endpoints: ["` + endpointName + `"]
      node_prefixes: [` + prefixesYAML + `]
`
	pub, priv, err := grant.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	g, canonical, err := grant.ParseYAML([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	sig := grant.Sign(priv, canonical)

	grantPath := filepath.Join(dir, "grant.yaml")
	if err := os.WriteFile(grantPath, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := grant.WriteSignatureFile(grantPath+".sig", sig); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "trusted.pub")
	if err := grant.WritePublicKeyFile(pubPath, pub); err != nil {
		t.Fatal(err)
	}

	return policy.NewGrantEngine("fieldlink-test", grantPath, pubPath, nil)
}
