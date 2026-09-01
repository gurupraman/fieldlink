# FieldLink — project context

An MCP server for systems that have no API: Modbus, OPC-UA, SMB shares, on-prem SQL.
Single static Go binary. No Docker, no Kubernetes, no cloud account.

**Read `docs/design.md` before writing code.** It is the full technical design and it is
the source of truth for architecture decisions. This file is the short version.

## Status

Pre-alpha. Nothing is built yet. Week 1 of a 6-week solo build (evenings and weekends).

## What we are building

A binary that runs on a plant network — an industrial PC, a Raspberry Pi, a Moxa box — and
exposes local industrial and legacy systems to any MCP client as tools.

The gap it fills: every existing MCP gateway (Bifrost, agentgateway, MCPX, MetaMCP) assumes
the tool is *already* an MCP server on HTTP or stdio. They route; they do not reach a PLC.
Nothing ships a sub-20 MB static binary that speaks Modbus and OPC-UA and presents them as
MCP tools.

## Hard constraints — do not violate these

1. **`CGO_ENABLED=0`.** Non-negotiable. It is what lets one binary run on Yocto, Alpine,
   OpenWrt and a twelve-year-old CentOS box. Every dependency is chosen to preserve it.
   Never add a dependency that needs cgo (no `godror`, no open62541 wrapper, no mattn/sqlite3).

2. **No write capabilities. At all.** Modbus function codes 5, 6, 15 and 16 are *not
   implemented* — not gated, not behind a flag, absent from the codebase. Same for
   `fs.write`, `db.exec`, `proc.exec`. A bad coil write moves a physical actuator, and there
   is a short path from a prompt injection in a maintenance PDF to a machine starting while
   someone's hands are inside it. If a task seems to need a write, stop and ask.

3. **Policy check on every call.** Grant signature, expiry, agent binding and constraints are
   verified per `tools/call`, never cached as a "grant is valid" boolean. That cache is
   exactly the bug this design exists to prevent.

4. **Fail closed, loudly.** Missing/expired/unverifiable grant → server starts, advertises
   zero tools, returns a clear reason on every call. Never start with permissions open.

5. **Scope discipline.** The failure mode for this project is building a platform. No
   designer, no fleet console, no multi-tenancy, no cloud control plane, no connector
   framework. If a change adds one of those, it is out of scope for v0.1.

## Architecture in one paragraph

MCP client → MCP server layer (stdio or Streamable HTTP) → policy engine (the trust
boundary) → capability executor → audit log → response. The policy engine verifies an
Ed25519-signed grant against a pinned public key held locally; the private key lives offline
and never touches this host. Capabilities absent from the grant are never advertised in
`tools/list`.

## Capabilities (v0.1, all read-only)

Originally fixed at six ("six capabilities, no more" — see HANDOFF.md). `soap.call`
is a deliberate, documented exception for legacy SOAP/WSDL-only systems — see
docs/trust-model.md for why it can't offer the same wire-enforced read-only
guarantee the other six do. Don't treat its existence as license to add an eighth
without the same level of justification.

| Capability | MCP tool | Notes |
|---|---|---|
| `fs.read` | `read_file` | glob-constrained, symlinks resolved before matching |
| `fs.list` | `list_directory` | same |
| `db.query` | `query_database` | named datasources only; `SELECT`/`WITH` only; bound params |
| `http.request` | `call_internal_http` | GET/HEAD; CIDR check after DNS; metadata endpoints hard-blocked |
| `device.modbus.read` | `read_modbus` | FC 1–4 only; symbolic register names from a register map |
| `device.opcua.read` | `read_opcua`, `browse_opcua` | anonymous/username auth; both gated by the same `node_prefixes` grant constraint |
| `soap.call` | `call_soap` | named, pre-declared XML templates only; no WSDL parsing; operator attests read-only |

## Stack

Go. `simonvetter/modbus`, `gopcua/opcua`, `hirochachacha/go-smb2`,
`microsoft/go-mssqldb` / `sijms/go-ora` / `jackc/pgx`, `bbolt`, `filippo.io/age`.
MCP: official Go SDK or `mark3labs/mcp-go` — pick whichever is better maintained, check first.

## Conventions

- Executors are transport-agnostic. A gRPC transport lands in v0.2; do not couple executor
  code to the MCP layer.
- Denial messages never echo host paths or reveal what the grant *would* have allowed.
- Tool execution failures return `isError: true` in a **successful** JSON-RPC result, so the
  model can react. Only protocol failures become JSON-RPC error objects.
- Every tool declares an `outputSchema` and returns `structuredContent`.
- Audit records store parameters as a digest, never in the clear.
- Serial and Modbus RTU need a per-device mutex. Getting this wrong produces corrupted reads
  that look like hardware faults — very expensive to debug in the field.

## Build order

1. Skeleton, config, MCP server layer, `fs.read` / `fs.list`
2. Policy engine, grant format, Ed25519 verify, `fieldlink grant sign`
3. `device.modbus.read` + register maps + simulator + `fieldlink demo`
4. `db.query`, `http.request`, resources, prompts, audit chain
5. Docs, CI cross-compile matrix, signed release
6. Public

`fieldlink demo` (step 3) is a headline feature, not a convenience — most evaluators do not
own a PLC, and it is what makes the README reproducible.

## Open blocker

None. Employment IP assignment was flagged in the original design as a gate on
publishing; the author's role does not fall under IP assignment, so this does not
apply and is not a blocker on pushing publicly.
