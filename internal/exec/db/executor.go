package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"  // registers driver "pgx"
	_ "github.com/microsoft/go-mssqldb" // registers driver "sqlserver"
	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	_ "github.com/sijms/go-ora/v2" // registers driver "oracle"

	"github.com/gurupraman/fieldlink/internal/config"
	"github.com/gurupraman/fieldlink/internal/policy"
)

// sqlDriverNames maps config.yaml's driver names to Go's database/sql
// driver names, which don't always match (design.md §9, §11).
var sqlDriverNames = map[string]string{
	"postgres": "pgx",
	"mssql":    "sqlserver",
	"oracle":   "oracle",
}

const (
	defaultMaxRows  = 1000
	hardMaxRowsCeil = 10000 // enforced even if config/grant set something higher
)

// Executor implements query_database. The database account FieldLink
// connects with must itself be read-only — the statement-type check and
// bound parameters are defense in depth, not a substitute for that
// (design.md §6.5, SECURITY.md).
type Executor struct {
	Policy      policy.Engine
	Datasources map[string]config.Datasource

	mu  sync.Mutex
	dbs map[string]*sql.DB
}

func NewExecutor(eng policy.Engine, datasources map[string]config.Datasource) *Executor {
	return &Executor{
		Policy:      eng,
		Datasources: datasources,
		dbs:         make(map[string]*sql.DB),
	}
}

type QueryDatabaseInput struct {
	Datasource string `json:"datasource" jsonschema:"configured datasource name"`
	SQL        string `json:"sql" jsonschema:"a single SELECT or WITH statement"`
	Params     []any  `json:"params,omitempty" jsonschema:"bound parameters, positional"`
	MaxRows    int    `json:"max_rows,omitempty" jsonschema:"maximum rows to return; capped by the grant and by this build's hard limit"`
}

type QueryDatabaseOutput struct {
	Datasource string           `json:"datasource"`
	Columns    []string         `json:"columns"`
	Rows       []map[string]any `json:"rows"`
	RowCount   int              `json:"row_count"`
	Truncated  bool             `json:"truncated"`
}

func (e *Executor) QueryDatabase(ctx context.Context, _ *gomcp.CallToolRequest, in QueryDatabaseInput) (*gomcp.CallToolResult, QueryDatabaseOutput, error) {
	if in.Datasource == "" || in.SQL == "" {
		return denied("datasource and sql are required"), QueryDatabaseOutput{}, nil
	}

	ds, ok := e.Datasources[in.Datasource]
	if !ok {
		return denied("datasource is not configured"), QueryDatabaseOutput{}, nil
	}

	if err := ValidateStatement(in.SQL); err != nil {
		return denied("only a single SELECT or WITH statement is permitted"), QueryDatabaseOutput{}, nil
	}

	maxRows := in.MaxRows
	if maxRows <= 0 {
		maxRows = defaultMaxRows
	}

	decision := e.Policy.Authorize(ctx, "db.query", map[string]any{
		"datasource": in.Datasource,
		"max_rows":   maxRows,
	})
	if !decision.Allowed {
		return denied(decision.Reason), QueryDatabaseOutput{}, nil
	}
	if maxRows > hardMaxRowsCeil {
		maxRows = hardMaxRowsCeil
	}

	conn, err := e.connFor(in.Datasource, ds)
	if err != nil {
		return denied("could not connect to datasource"), QueryDatabaseOutput{}, nil
	}

	queryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	rows, err := conn.QueryContext(queryCtx, in.SQL, in.Params...)
	if err != nil {
		return denied("query failed"), QueryDatabaseOutput{}, nil
	}
	defer rows.Close()

	columns, resultRows, truncated, err := scanRows(rows, maxRows)
	if err != nil {
		return denied("query failed while reading results"), QueryDatabaseOutput{}, nil
	}

	out := QueryDatabaseOutput{
		Datasource: in.Datasource,
		Columns:    columns,
		Rows:       resultRows,
		RowCount:   len(resultRows),
		Truncated:  truncated,
	}
	return nil, out, nil
}

func (e *Executor) connFor(name string, ds config.Datasource) (*sql.DB, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if db, ok := e.dbs[name]; ok {
		return db, nil
	}

	driverName, ok := sqlDriverNames[ds.Driver]
	if !ok {
		return nil, fmt.Errorf("unknown driver %q", ds.Driver)
	}
	dsn := os.Getenv(ds.DSNEnv)
	if dsn == "" {
		return nil, fmt.Errorf("environment variable %s is not set", ds.DSNEnv)
	}

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	maxOpen := ds.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = 4
	}
	db.SetMaxOpenConns(maxOpen)

	e.dbs[name] = db
	return db, nil
}

func scanRows(rows *sql.Rows, maxRows int) (columns []string, out []map[string]any, truncated bool, err error) {
	columns, err = rows.Columns()
	if err != nil {
		return nil, nil, false, err
	}

	for rows.Next() {
		if len(out) >= maxRows {
			truncated = true
			break
		}
		vals := make([]any, len(columns))
		ptrs := make([]any, len(columns))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err = rows.Scan(ptrs...); err != nil {
			return nil, nil, false, err
		}
		row := make(map[string]any, len(columns))
		for i, col := range columns {
			row[col] = normalizeValue(vals[i])
		}
		out = append(out, row)
	}
	if err = rows.Err(); err != nil {
		return nil, nil, false, err
	}
	return columns, out, truncated, nil
}

// normalizeValue converts driver-specific scan results into JSON-friendly
// values. Drivers commonly return text/varchar columns as []byte.
func normalizeValue(v any) any {
	switch t := v.(type) {
	case []byte:
		return string(t)
	case time.Time:
		return t.UTC().Format(time.RFC3339)
	default:
		return t
	}
}

func denied(reason string) *gomcp.CallToolResult {
	return &gomcp.CallToolResult{
		IsError: true,
		Content: []gomcp.Content{&gomcp.TextContent{Text: "Denied: " + reason}},
	}
}
