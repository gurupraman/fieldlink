package db

import (
	"context"
	"fmt"
)

// ColumnInfo is one column, as surfaced by the
// fieldlink://datasources/{id}/schema resource (design.md §4.4): "Tables,
// columns and types visible to the read-only user."
type ColumnInfo struct {
	Table  string `json:"table"`
	Column string `json:"column"`
	Type   string `json:"type"`
}

// schemaQueries are each dialect's standard introspection query. Oracle has
// no information_schema; the others do, though a real deployment may need
// to adjust the schema/owner filter for its own layout — this is a
// best-effort default, not a guarantee of completeness.
var schemaQueries = map[string]string{
	"postgres": `SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = 'public' ORDER BY table_name, ordinal_position`,
	"mssql":    `SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS ORDER BY TABLE_NAME, ORDINAL_POSITION`,
	"oracle":   `SELECT table_name, column_name, data_type FROM user_tab_columns ORDER BY table_name, column_id`,
}

// Schema introspects the given datasource's visible tables and columns. It
// does not go through Authorize/ValidateStatement — resources are
// informational content gated at the coarser Granted(capability) level by
// the MCP layer, not a second enforcement point (Authorize governs actual
// query_database calls).
func (e *Executor) Schema(ctx context.Context, name string) ([]ColumnInfo, error) {
	ds, ok := e.Datasources[name]
	if !ok {
		return nil, fmt.Errorf("datasource %q is not configured", name)
	}
	q, ok := schemaQueries[ds.Driver]
	if !ok {
		return nil, fmt.Errorf("no schema introspection query for driver %q", ds.Driver)
	}

	conn, err := e.connFor(name, ds)
	if err != nil {
		return nil, err
	}

	rows, err := conn.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ColumnInfo
	for rows.Next() {
		var c ColumnInfo
		if err := rows.Scan(&c.Table, &c.Column, &c.Type); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
