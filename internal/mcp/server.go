// Package server wires FieldLink's executors into the Model Context
// Protocol surface described in docs/design.md §4: tool registration,
// annotations, and the stdio transport. Package name is "server" (not
// "mcp") so callers can still import the official SDK's mcp package in the
// same file without an alias.
package server

import (
	"context"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gurupraman/fieldlink/internal/config"
	dbexec "github.com/gurupraman/fieldlink/internal/exec/db"
	modbusexec "github.com/gurupraman/fieldlink/internal/exec/device/modbus"
	opcuaexec "github.com/gurupraman/fieldlink/internal/exec/device/opcua"
	fsexec "github.com/gurupraman/fieldlink/internal/exec/fs"
	httpexec "github.com/gurupraman/fieldlink/internal/exec/httpx"
	"github.com/gurupraman/fieldlink/internal/policy"
)

const (
	name    = "fieldlink"
	version = "0.1.0-dev"

	// instructions is returned in initialize and is load-bearing per
	// design.md §4.2: it is how the model learns this server is
	// read-only and that it must not guess at raw values.
	instructions = "FieldLink is read-only. No tool here writes to any file, " +
		"database, or device — write operations are not implemented, not " +
		"just disabled. Only capabilities present in the active grant are " +
		"listed; a tool's absence means it was never authorised, not that " +
		"it failed. Treat a denied call as final rather than retrying."
)

// New builds the FieldLink MCP server and registers every tool and
// resource this build implements. eng is consulted on every call — see
// internal/policy for why it is passed in rather than constructed here.
// cfg may be nil in tests that only exercise fs.read/fs.list.
func New(eng policy.Engine, cfg *config.Config) *gosdk.Server {
	if cfg == nil {
		cfg = &config.Config{}
	}

	s := gosdk.NewServer(&gosdk.Implementation{
		Name:    name,
		Version: version,
	}, &gosdk.ServerOptions{
		Instructions: instructions,
	})

	fsExec := &fsexec.Executor{Policy: eng}
	modbusExec := modbusexec.NewExecutor(eng, cfg.Devices)
	opcuaExec := opcuaexec.NewExecutor(eng, cfg.OPCUAEndpoints)
	httpExec := &httpexec.Executor{Policy: eng}
	dbExec := dbexec.NewExecutor(eng, cfg.Datasources)

	// A capability absent from the grant must never appear in tools/list
	// (design.md §4.3) — Granted() is checked once here at startup. This
	// does not weaken per-call enforcement: every executor still calls
	// eng.Authorize on every invocation of a tool that *is* registered.
	//
	// TODO(later): design.md §6.4 describes live mid-session expiry —
	// emitting notifications/tools/list_changed and serving an empty list
	// when a grant expires without a restart. Not implemented yet; today
	// the advertised list reflects the grant's state at startup, while
	// Authorize always re-verifies fresh and fails closed regardless.
	if eng.Granted("fs.read") {
		gosdk.AddTool(s, &gosdk.Tool{
			Name:  "read_file",
			Title: "Read file",
			Description: "Read a file's contents. Read-only: this tool cannot write, " +
				"create, or delete. Files larger than max_bytes return a SHA-256 " +
				"digest instead of content.",
			Annotations: &gosdk.ToolAnnotations{
				ReadOnlyHint:    true,
				DestructiveHint: boolPtr(false),
				IdempotentHint:  true,
				OpenWorldHint:   boolPtr(false),
			},
		}, fsExec.ReadFile)
	}

	if eng.Granted("fs.list") {
		gosdk.AddTool(s, &gosdk.Tool{
			Name:  "list_directory",
			Title: "List directory",
			Description: "List entries in a directory, optionally filtered by glob " +
				"and recursed. Read-only.",
			Annotations: &gosdk.ToolAnnotations{
				ReadOnlyHint:    true,
				DestructiveHint: boolPtr(false),
				IdempotentHint:  true,
				OpenWorldHint:   boolPtr(false),
			},
		}, fsExec.ListDirectory)
	}

	if eng.Granted("device.modbus.read") {
		gosdk.AddTool(s, &gosdk.Tool{
			Name:  "read_modbus",
			Title: "Read Modbus register",
			Description: "Read a named register from a configured Modbus device. " +
				"Register names come from the device's register map, available as " +
				"a resource. Returns a decoded, scaled value with units. Read-only: " +
				"write function codes are not implemented.",
			Annotations: &gosdk.ToolAnnotations{
				ReadOnlyHint:    true,
				DestructiveHint: boolPtr(false),
				IdempotentHint:  true,
				OpenWorldHint:   boolPtr(false),
			},
		}, modbusExec.ReadModbus)
	}

	if eng.Granted("device.opcua.read") {
		gosdk.AddTool(s, &gosdk.Tool{
			Name:  "read_opcua",
			Title: "Read OPC-UA nodes",
			Description: "Read one or more OPC-UA node values by node ID from a " +
				"configured endpoint. Read-only: no write service is implemented.",
			Annotations: &gosdk.ToolAnnotations{
				ReadOnlyHint:    true,
				DestructiveHint: boolPtr(false),
				IdempotentHint:  true,
				OpenWorldHint:   boolPtr(false),
			},
		}, opcuaExec.ReadOPCUA)
	}

	if eng.Granted("http.request") {
		gosdk.AddTool(s, &gosdk.Tool{
			Name:  "call_internal_http",
			Title: "Call internal HTTP service",
			Description: "GET or HEAD an internal HTTP URL. Redirects are not " +
				"followed automatically. Read-only: no other methods are supported.",
			Annotations: &gosdk.ToolAnnotations{
				ReadOnlyHint:    true,
				DestructiveHint: boolPtr(false),
				IdempotentHint:  true,
				OpenWorldHint:   boolPtr(true),
			},
		}, httpExec.CallInternalHTTP)
	}

	if eng.Granted("db.query") {
		gosdk.AddTool(s, &gosdk.Tool{
			Name:  "query_database",
			Title: "Query database",
			Description: "Run a single read-only SELECT or WITH query against a " +
				"named datasource, with bound parameters. Read-only: statements " +
				"other than SELECT/WITH are rejected, and the database account " +
				"FieldLink connects with should itself be read-only.",
			Annotations: &gosdk.ToolAnnotations{
				ReadOnlyHint:    true,
				DestructiveHint: boolPtr(false),
				IdempotentHint:  true,
				OpenWorldHint:   boolPtr(false),
			},
		}, dbExec.QueryDatabase)
	}

	registerResources(s, eng, cfg, dbExec)
	registerPrompts(s)

	return s
}

// RunStdio runs the server over stdio until the client disconnects or ctx
// is cancelled. Logs must never go to stdout — that would corrupt the
// JSON-RPC stream (design.md §4.1).
func RunStdio(ctx context.Context, s *gosdk.Server) error {
	return s.Run(ctx, &gosdk.StdioTransport{})
}

func boolPtr(b bool) *bool { return &b }
