package db

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/gurupraman/fieldlink/internal/config"
	"github.com/gurupraman/fieldlink/internal/grant"
	"github.com/gurupraman/fieldlink/internal/policy"
)

// These tests run against a real local Postgres, started separately with:
//
//	docker run -d --name fieldlink-pg-test -e POSTGRES_PASSWORD=test \
//	  -e POSTGRES_DB=fieldlink_test -p 15432:5432 postgres:16-alpine
//	docker exec fieldlink-pg-test psql -U postgres -d fieldlink_test -c \
//	  "CREATE TABLE fault_log (id serial primary key, device text not null, \
//	    code int not null, message text, logged_at timestamptz not null default now()); \
//	   INSERT INTO fault_log (device, code, message) VALUES \
//	    ('line2-plc', 12, 'High temperature'), ('line2-plc', 0, 'No fault'), \
//	    ('line3-plc', 7, 'Sensor fault');"
//
// They're skipped automatically if FIELDLINK_TEST_PG_DSN isn't set, so the
// rest of the suite doesn't require Docker.
func testExecutor(t *testing.T) *Executor {
	t.Helper()
	dsn := os.Getenv("FIELDLINK_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("FIELDLINK_TEST_PG_DSN not set; skipping live Postgres test")
	}
	os.Setenv("FIELDLINK_TEST_PG_DSN_ACTUAL", dsn)

	// Ceiling must be >= the executor's own defaultMaxRows (1000), since
	// callers in these tests mostly leave MaxRows unset.
	eng := grantedDBEngine(t, "fieldlink_test", 10000)
	ds := map[string]config.Datasource{
		"fieldlink_test": {Driver: "postgres", DSNEnv: "FIELDLINK_TEST_PG_DSN_ACTUAL", MaxOpenConns: 2},
	}
	return NewExecutor(eng, ds)
}

func grantedDBEngine(t *testing.T, datasource string, maxRows int) policy.Engine {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := grant.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	yaml := `
version: 1
grant_id: 01J9Z8Q7K3M4N5P6R7S8T9V0W1
agent_id: fieldlink-test
issued_at: ` + time.Now().Add(-1*time.Hour).UTC().Format(time.RFC3339) + `
expires_at: ` + time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339) + `
issuer: security@example.com
capabilities:
  - capability: db.query
    constraints:
      datasources: ["` + datasource + `"]
      max_rows: ` + itoa(maxRows) + `
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

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func TestQueryDatabase_RealPostgres_SelectRows(t *testing.T) {
	exec := testExecutor(t)

	_, out, err := exec.QueryDatabase(context.Background(), nil, QueryDatabaseInput{
		Datasource: "fieldlink_test",
		SQL:        "SELECT device, code, message FROM fault_log WHERE device = $1 ORDER BY code",
		Params:     []any{"line2-plc"},
	})
	if err != nil {
		t.Fatalf("QueryDatabase: %v", err)
	}
	if out.RowCount != 2 {
		t.Fatalf("row_count = %d, want 2", out.RowCount)
	}
	if out.Rows[0]["device"] != "line2-plc" {
		t.Errorf("rows[0].device = %v", out.Rows[0]["device"])
	}
	if out.Rows[0]["code"] != int64(0) && out.Rows[0]["code"] != int32(0) {
		t.Errorf("rows[0].code = %v (%T), want 0", out.Rows[0]["code"], out.Rows[0]["code"])
	}
}

func TestQueryDatabase_RealPostgres_RejectsNonSelect(t *testing.T) {
	exec := testExecutor(t)

	result, _, err := exec.QueryDatabase(context.Background(), nil, QueryDatabaseInput{
		Datasource: "fieldlink_test",
		SQL:        "DELETE FROM fault_log WHERE code = 0",
	})
	if err != nil {
		t.Fatalf("QueryDatabase: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true for a DELETE statement")
	}

	// Prove it was genuinely rejected, not silently executed: the row is
	// still there.
	_, out, err := exec.QueryDatabase(context.Background(), nil, QueryDatabaseInput{
		Datasource: "fieldlink_test",
		SQL:        "SELECT count(*) AS n FROM fault_log WHERE code = 0",
	})
	if err != nil {
		t.Fatalf("QueryDatabase (verify): %v", err)
	}
	n := out.Rows[0]["n"]
	if n != int64(1) {
		t.Fatalf("expected the DELETE to have been blocked, count = %v", n)
	}
}

func TestQueryDatabase_RealPostgres_RejectsStackedStatements(t *testing.T) {
	exec := testExecutor(t)

	result, _, err := exec.QueryDatabase(context.Background(), nil, QueryDatabaseInput{
		Datasource: "fieldlink_test",
		SQL:        "SELECT 1; DELETE FROM fault_log",
	})
	if err != nil {
		t.Fatalf("QueryDatabase: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true for a stacked statement")
	}
}

func TestQueryDatabase_RealPostgres_DeniesUngrantedDatasource(t *testing.T) {
	dsn := os.Getenv("FIELDLINK_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("FIELDLINK_TEST_PG_DSN not set; skipping live Postgres test")
	}
	os.Setenv("FIELDLINK_TEST_PG_DSN_ACTUAL2", dsn)

	eng := grantedDBEngine(t, "some_other_datasource", 100)
	ds := map[string]config.Datasource{
		"fieldlink_test": {Driver: "postgres", DSNEnv: "FIELDLINK_TEST_PG_DSN_ACTUAL2", MaxOpenConns: 2},
	}
	exec := NewExecutor(eng, ds)

	result, _, err := exec.QueryDatabase(context.Background(), nil, QueryDatabaseInput{
		Datasource: "fieldlink_test",
		SQL:        "SELECT 1",
	})
	if err != nil {
		t.Fatalf("QueryDatabase: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true for a datasource not present in the grant")
	}
}

func TestQueryDatabase_RealPostgres_DeniesMaxRowsAboveGrantCeiling(t *testing.T) {
	dsn := os.Getenv("FIELDLINK_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("FIELDLINK_TEST_PG_DSN not set; skipping live Postgres test")
	}
	os.Setenv("FIELDLINK_TEST_PG_DSN_ACTUAL3", dsn)

	eng := grantedDBEngine(t, "fieldlink_test", 2)
	ds := map[string]config.Datasource{
		"fieldlink_test": {Driver: "postgres", DSNEnv: "FIELDLINK_TEST_PG_DSN_ACTUAL3", MaxOpenConns: 2},
	}
	exec := NewExecutor(eng, ds)

	result, _, err := exec.QueryDatabase(context.Background(), nil, QueryDatabaseInput{
		Datasource: "fieldlink_test",
		SQL:        "SELECT * FROM fault_log",
		MaxRows:    100, // requested above the grant's ceiling of 2
	})
	if err != nil {
		t.Fatalf("QueryDatabase: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected isError:true for max_rows above the grant's ceiling")
	}
}

func TestQueryDatabase_RealPostgres_TruncatesAtMaxRows(t *testing.T) {
	dsn := os.Getenv("FIELDLINK_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("FIELDLINK_TEST_PG_DSN not set; skipping live Postgres test")
	}
	os.Setenv("FIELDLINK_TEST_PG_DSN_ACTUAL4", dsn)

	eng := grantedDBEngine(t, "fieldlink_test", 2)
	ds := map[string]config.Datasource{
		"fieldlink_test": {Driver: "postgres", DSNEnv: "FIELDLINK_TEST_PG_DSN_ACTUAL4", MaxOpenConns: 2},
	}
	exec := NewExecutor(eng, ds)

	// fault_log has 3 seed rows; requesting exactly the grant's ceiling
	// (2, itself allowed) should come back truncated.
	_, out, err := exec.QueryDatabase(context.Background(), nil, QueryDatabaseInput{
		Datasource: "fieldlink_test",
		SQL:        "SELECT * FROM fault_log",
		MaxRows:    2,
	})
	if err != nil {
		t.Fatalf("QueryDatabase: %v", err)
	}
	if out.RowCount != 2 {
		t.Fatalf("row_count = %d, want 2", out.RowCount)
	}
	if !out.Truncated {
		t.Fatal("expected truncated:true when more rows exist than max_rows")
	}
}
