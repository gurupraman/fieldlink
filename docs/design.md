# FieldLink — Technical Design Document

**An MCP server for systems that have no API.**

**Version:** 0.1 — design for first public release
**Author:** GetSetAI
**Date:** August 2026
**Status:** Design. Not yet built.
**License (planned):** Apache-2.0

> **Naming note.** `FieldLink` is provisional. Whatever is chosen, the repository
> *description* should carry the terms people search for:
> "MCP server for Modbus, OPC-UA, SMB shares and on-prem SQL — one Go binary, no Docker."

---

## 1. Problem statement

MCP has solved tool access for systems that speak HTTP. It has not solved access
to systems that speak anything else.

An AI agent today cannot:

| Target | Why it is unreachable |
|---|---|
| Modbus TCP register on a line controller | Binary protocol over TCP/502. No HTTP, no auth, no JSON. |
| OPC-UA node on a SCADA server | Binary or SOAP-ish protocol, certificate handshake, hierarchical address space. |
| CSV written to an SMB share by a machine from 2009 | SMB2 dialect, NTLM auth, no API of any kind. |
| Table in an on-prem MSSQL or Oracle instance | TDS / TNS wire protocols. No network route from outside. |
| Internal HTTP service on an isolated segment | Speaks HTTP, but has no route to the internet in either direction. |

These systems will never get REST APIs. They sit on networks where nobody will
install Docker, and where "just run it in Kubernetes" is not a sentence anyone
says out loud.

**FieldLink is a single static binary that runs on that network, speaks those
protocols, and presents them to any MCP client as tools — under a permission
model the AI cannot alter.**

### 1.1 What exists today, and why it does not close this

| Category | Examples | Gap |
|---|---|---|
| MCP gateways / aggregators | Bifrost, agentgateway, MCPX, MetaMCP, MCPJungle | Assume the tool is *already* an MCP server on HTTP or stdio. They route and govern; they do not reach a PLC. |
| MCP security proxies | mcp-firewall | Policy and audit around MCP traffic. Same assumption. **Complementary** — FieldLink can sit behind one. |
| On-prem agent platforms | Adopt AI, SpaceFlow, VDF AI, MintMCP | Require Kubernetes or a cloud account. Enterprise sales motion, enterprise price. |
| RPA / automation suites | UiPath Automation Suite, Nintex | Genuine on-prem capability, but the client must operate a platform team. |
| Self-hosted workflow tools | n8n | One instance per site, no installable agent, nothing for ARM industrial hardware. |

Nothing in the ecosystem is a sub-20 MB static binary that runs on a Moxa
industrial PC or a Raspberry Pi and turns industrial and legacy protocols into
MCP tools.

---

## 2. Scope

### 2.1 In scope for v0.1

1. Single static Go binary — `linux/amd64`, `linux/arm64`, `linux/arm/v7`. `CGO_ENABLED=0`.
2. Full MCP server implementation: stdio and Streamable HTTP transports.
3. Six **read-only** capabilities exposed as MCP tools (§5).
4. MCP **resources** for register maps and database schemas (§4.4).
5. MCP **prompts** for the three most common diagnostic workflows (§4.5).
6. Offline-signed capability grants, verified locally on every call (§6).
7. Append-only, hash-chained audit log (§8).
8. `fieldlink demo` — built-in device simulator, so evaluation needs no hardware (§10).

### 2.2 Out of scope for v0.1

- **All write operations.** See §2.3.
- Any cloud component: no control plane, no account, no enrolment, no telemetry.
- Multi-tenancy, RBAC, web UI.
- Windows (v0.2 — the industrial edge is Linux, and MSI code-signing costs money
  that does not yet exist).
- Model hosting or routing. FieldLink is a tool provider; the caller brings the model.
- MCP `sampling` and `roots`. Server-initiated sampling is not needed and widens
  the trust surface for no benefit here.

### 2.3 On write capabilities — a deliberate refusal

v0.1 will not write to industrial control equipment, and this is a design
position, not a scheduling decision.

A bad file write corrupts a file. A bad Modbus coil write moves a physical
actuator. There is a real, short path from a prompt injection embedded in a
maintenance PDF to a machine starting while somebody's hands are inside it. That
path must not exist in a project that is one engineer's evenings with no safety
review behind it.

Write function codes are therefore **not implemented** rather than gated. There
is no code path to enable by accident, and no configuration flag that a hurried
operator can flip.

The correct home for OT writes is behind an interlock the software does not
control. That is a v1.0 conversation with a customer who has a safety case.

**This refusal belongs in the README, not the appendix.** It is also the only
posture that gets a plant engineer to try the tool at all, so the commercial and
the ethical argument point the same way.

---

## 3. System context

```
        ╔═══════════════════════════════════════════════════════════════╗
        ║  IT SEGMENT  /  ENGINEER WORKSTATION                          ║
        ║                                                               ║
        ║   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        ║
        ║   │ Claude Code  │  │ Claude       │  │ Custom agent │        ║
        ║   │ Cursor       │  │ Desktop      │  │ n8n · script │        ║
        ║   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘        ║
        ║          └─────────────────┼─────────────────┘                ║
        ╚════════════════════════════╪══════════════════════════════════╝
                                     │  MCP  ·  JSON-RPC 2.0
                                     │  stdio  |  Streamable HTTP
        ╔════════════════════════════╪══════════════════════════════════╗
        ║  OT / PLANT SEGMENT        ▼                                  ║
        ║                  ┌───────────────────────┐                    ║
        ║                  │      FIELDLINK        │                    ║
        ║                  │  one static binary    │                    ║
        ║                  │  ~18 MB · no runtime  │                    ║
        ║                  └───────────┬───────────┘                    ║
        ║                              │                                ║
        ║   ┌──────────┬───────────┬───┴──────┬────────────┬─────────┐  ║
        ║   ▼          ▼           ▼          ▼            ▼         ▼  ║
        ║ ┌──────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐ ┌────┐ ║
        ║ │ SMB  │ │ MSSQL  │ │Internal│ │ Modbus │ │  OPC-UA  │ │NFS │ ║
        ║ │share │ │ Oracle │ │ HTTP   │ │TCP/RTU │ │  server  │ │    │ ║
        ║ │      │ │ Postgres│ │service │ │  PLC   │ │  SCADA   │ │    │ ║
        ║ └──────┘ └────────┘ └────────┘ └────────┘ └──────────┘ └────┘ ║
        ╚═══════════════════════════════════════════════════════════════╝

   FieldLink is the only process that spans the boundary. Nothing above the
   line ever opens a socket to anything below it.
```

### 3.1 Deployment shapes

```
  SHAPE A — Workstation (evaluation, development)
  ┌─────────────────────────────────────────────┐
  │  Laptop                                      │
  │   Claude Code ──stdio──► fieldlink ──► sim  │
  └─────────────────────────────────────────────┘
   Setup time: ~60 seconds. This is the funnel.

  SHAPE B — Site gateway (real use)
  ┌────────────────┐        ┌──────────────────────────────┐
  │ Engineer       │  HTTP  │ Industrial PC / Pi           │
  │ Claude Desktop │───────►│ fieldlink :8765 (LAN-scoped) │──► PLC, share, DB
  └────────────────┘        └──────────────────────────────┘
   The gateway is often the only host that can see both segments.

  SHAPE C — Behind an existing MCP gateway (governed orgs)
  ┌──────────┐   ┌──────────────┐   ┌───────────┐
  │ Clients  │──►│ mcp-firewall │──►│ fieldlink │──► OT systems
  │          │   │ / MCP gateway│   │           │
  └──────────┘   └──────────────┘   └───────────┘
   Positions FieldLink as complementary to the gateway projects rather than
   competing with them — which is also the honest technical relationship.
```

---

## 4. MCP surface

### 4.1 Protocol and transports

FieldLink implements MCP over JSON-RPC 2.0 on two transports.

| Transport | Use | Notes |
|---|---|---|
| **stdio** | Default. Client spawns FieldLink as a subprocess. | No network exposure at all. Newline-delimited JSON-RPC on stdin/stdout. Logs go to stderr — never stdout, which would corrupt the stream. |
| **Streamable HTTP** | Site-gateway deployments where the client is on another host. | Single `/mcp` endpoint. POST for requests, optional SSE upgrade for server→client streams. `Mcp-Session-Id` header for session continuity. |

**HTTP transport hardening**, per the MCP specification's own guidance:

- Binds `127.0.0.1` by default. Binding to a routable address requires an
  explicit `--allow-remote` flag, and logs a warning at every startup.
- Validates the `Origin` header on every request, rejecting anything not in the
  configured allow-list. This is the DNS-rebinding defence.
- Requires a bearer token when `--allow-remote` is set. There is no
  unauthenticated remote mode.
- Rejects requests whose `MCP-Protocol-Version` header names an unsupported version.

### 4.2 Session lifecycle

```
CLIENT                                              FIELDLINK
  │                                                     │
  │──── initialize ────────────────────────────────────►│
  │     { protocolVersion, capabilities, clientInfo }   │
  │                                                     │ load config
  │                                                     │ read grant.yaml
  │                                                     │ verify Ed25519 sig
  │                                                     │ build tool set
  │◄─── result ─────────────────────────────────────────│
  │     { protocolVersion, capabilities: {              │
  │         tools:     { listChanged: true },           │
  │         resources: { listChanged: true,             │
  │                      subscribe: false },            │
  │         prompts:   { listChanged: false },          │
  │         logging:   {} },                            │
  │       serverInfo: { name, version },                │
  │       instructions: "..." }                         │
  │                                                     │
  │──── notifications/initialized ─────────────────────►│
  │                                                     │
  │──── tools/list ────────────────────────────────────►│
  │◄─── only capabilities the GRANT authorises ─────────│
  │                                                     │
  │──── tools/call ────────────────────────────────────►│
  │     { name: "read_modbus", arguments: {...} }       │
  │                                                     │ ┌─────────────────┐
  │                                                     │ │ policy → verify │
  │                                                     │ │ execute         │
  │                                                     │ │ audit append    │
  │                                                     │ └─────────────────┘
  │◄─── result { content[], structuredContent, isError }│
  │                                                     │
  │              ─── grant expires mid-session ───      │
  │◄─── notifications/tools/list_changed ───────────────│
  │──── tools/list ────────────────────────────────────►│
  │◄─── [] (empty)  ────────────────────────────────────│
  │                                                     │
```

The `instructions` field returned from `initialize` is load-bearing. It tells the
model that this server is read-only, that register names are symbolic, and that
`fault_code` values must be looked up in the resource rather than guessed. Models
misuse industrial tools far less when told the domain rules up front.

### 4.3 Tools — derived from the grant, not from code

A capability that the grant does not authorise **does not appear in
`tools/list`**. The model never sees a tool it cannot use, which removes an
entire class of wasted turns and confused retries.

```
 grant.yaml (signed)                 tools/list response
 ┌───────────────────────┐           ┌───────────────────────┐
 │ capabilities:         │           │ read_file             │
 │  - fs.read         ───┼──────────►│ query_database        │
 │  - db.query        ───┼──────────►│ read_modbus           │
 │  - device.modbus.read─┼──────────►│                       │
 │                       │           │ (list_directory,      │
 │  (fs.list, http.request,          │  call_internal_http,  │
 │   device.opcua.read absent)       │  read_opcua — absent) │
 └───────────────────────┘           └───────────────────────┘
```

**Tool annotations.** Every tool carries the MCP annotation hints, and given the
read-only stance they are unusually clean:

```json
{
  "name": "read_modbus",
  "title": "Read Modbus register",
  "description": "Read a named register from a configured Modbus device.
                  Register names come from the device's register map,
                  available as a resource. Returns a decoded, scaled
                  value with units.",
  "inputSchema": { "...": "..." },
  "outputSchema": { "...": "..." },
  "annotations": {
    "readOnlyHint": true,
    "destructiveHint": false,
    "idempotentHint": true,
    "openWorldHint": false
  }
}
```

`readOnlyHint: true` on every tool without exception is a claim the project can
make that almost no comparable server can, and clients that surface these hints
to users will show it.

**Structured output.** Every tool declares an `outputSchema` and returns
`structuredContent` alongside a human-readable `content` block. Callers get
typed data rather than parsing prose.

```json
{
  "content": [
    { "type": "text", "text": "boiler_temp = 84.3 degC (line2-plc, unit 1, FC3 @40021)" }
  ],
  "structuredContent": {
    "device": "line2-plc",
    "register": "boiler_temp",
    "value": 84.3,
    "unit": "degC",
    "raw": [17252, 26214],
    "quality": "good",
    "read_at": "2026-09-14T08:31:02.441Z"
  },
  "isError": false
}
```

**Error discipline.** The distinction matters and is frequently got wrong:

| Situation | Response |
|---|---|
| Unknown method, malformed params, bad protocol version | JSON-RPC **error** object (`-32601`, `-32602`, …) |
| Tool ran and failed — device timeout, SQL error, denied by grant | JSON-RPC **success** with `isError: true` in the result |

The second case must reach the model, because the model can act on it — retry a
different register, ask the user for a different path. A protocol-level error
typically cannot.

Denial messages never disclose what the grant *would* have allowed, and never
echo host paths. `"Denied: fs.read is not permitted for this path"` — not
`"Denied: /mnt/exports/**/*.csv does not match /etc/shadow"`.

**Progress.** `db.query` and multi-node `read_opcua` calls emit
`notifications/progress` against the request's `progressToken` so a slow query is
distinguishable from a hung one.

### 4.4 Resources

Resources are how the model learns the plant's vocabulary. Without them, an LLM
asked to "check the boiler" has no way to know that the register is called
`boiler_temp` and reads in tenths of a degree.

| URI | Content | MIME |
|---|---|---|
| `fieldlink://devices` | All configured devices, protocols, reachability status | `application/json` |
| `fieldlink://devices/{id}/registers` | Register map: names, types, units, ranges, descriptions | `application/json` |
| `fieldlink://devices/{id}/faults` | Fault-code lookup table for this device | `application/json` |
| `fieldlink://datasources` | Configured datasources, drivers, and read-only status | `application/json` |
| `fieldlink://datasources/{id}/schema` | Tables, columns and types visible to the read-only user | `application/json` |
| `fieldlink://grant` | The active grant, **redacted** — capabilities and expiry only | `application/json` |

Resources are filtered by the grant exactly as tools are: a device absent from
the grant is absent from `fieldlink://devices`.

`fieldlink://grant` exists so the model can explain to a user why something is
unavailable, instead of retrying a denied call four times.

### 4.5 Prompts

Three, covering the workflows that actually recur on a plant floor:

| Prompt | Arguments | Purpose |
|---|---|---|
| `diagnose_device` | `device`, optional `symptom` | Read the relevant register set, cross-reference the fault table, summarise. |
| `explain_fault_code` | `device`, `code` | Look up the code in the resource, explain in plain language, list likely causes. |
| `daily_line_summary` | `device`, `since` | Read the day's counters, compare against the register map's expected ranges. |

Prompts matter more here than in a typical MCP server because the users are
process engineers, not prompt engineers. They should not have to know how to ask.

---

## 5. Capabilities

All six are read-only. Each maps to exactly one MCP tool.

| Capability | Tool | Key parameters | Returns |
|---|---|---|---|
| `fs.read` | `read_file` | `path`, `encoding`, `max_bytes` | content, or digest + declared extract if oversized |
| `fs.list` | `list_directory` | `path`, `glob`, `recursive` | entries with size and mtime |
| `db.query` | `query_database` | `datasource`, `sql`, `params[]`, `max_rows` | typed rows |
| `http.request` | `call_internal_http` | `url`, `method` (GET/HEAD), `headers` | status, headers, body |
| `device.modbus.read` | `read_modbus` | `device`, `register` \| (`fc`,`address`,`count`) | decoded value + raw words |
| `device.opcua.read` | `read_opcua` | `endpoint`, `node_ids[]` | values, timestamps, status codes |

### 5.1 Executor notes

**`db.query`** takes a named `datasource` from config, never a connection string
from the caller. The model cannot choose which database to reach or which
credentials to use. Statements are parsed; only a top-level `SELECT` or `WITH` is
accepted, and multi-statement input is rejected outright. Parameters are bound,
never interpolated. The documentation states plainly that a too-permissive
database user defeats all of this and that the DB account must be read-only.

**`http.request`** is GET and HEAD only. The policy engine resolves the hostname
and rejects the request if the resolved IP falls outside the grant's CIDR list.
Cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`) are hard-blocked
regardless of grant. Redirects are not followed across hosts, and the IP is
re-checked after each redirect. SSRF is the obvious attack on this tool.

**`device.modbus.read`** implements function codes 1–4 only — coils, discrete
inputs, holding registers, input registers. Codes 5, 6, 15 and 16 are absent from
the codebase.

Decoding comes from a **register map** in config: type, word order, scale, unit.
This is not a convenience. Raw Modbus is a flat array of 16-bit words with no
type information, and an LLM asked to reconstruct a `float32` from two words with
vendor-specific word order will get it wrong in ways that look plausible. The map
makes the tool symbolic — the model asks for `boiler_temp`, not for "holding
register 40021, swap words, divide by ten".

**`device.opcua.read`** supports anonymous and username authentication against
the server's own security policy. Browse is supported. Subscriptions are v0.2.

**Serialisation.** Modbus RTU and serial devices permit one transaction at a
time per bus. A per-device mutex enforces this. Getting it wrong produces
corrupted reads that look exactly like hardware faults, which is a very expensive
class of bug to debug in the field.

---

## 6. Trust model

This is the part of the design that is genuinely uncommon. Everything else is
competent plumbing.

### 6.1 The problem

In the usual arrangement, the component that decides what an agent may do is the
same component that tells it what to do. Compromise the orchestrator — or
compromise the model with an injected instruction — and permissions widen
silently. The audit log is then written by the compromised component.

MCP inherits this. An MCP server that trusts its client trusts, transitively,
every document that client has read.

### 6.2 Offline-signed capability grants

FieldLink separates **who commands** from **who authorises**.

```
   ┌──────────────────────────────────────────────────────────────┐
   │  OFFLINE SIGNING KEY                                          │
   │  Ed25519 private key, held by the security owner.             │
   │  YubiKey, HSM, or an air-gapped machine.                      │
   │  NEVER present on the FieldLink host.                         │
   └───────────────────────────┬──────────────────────────────────┘
                               │ signs (JCS-canonical, domain-separated)
                               ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  GRANT                    grant.yaml  +  grant.yaml.sig       │
   │  Human-readable. Reviewable by a security team BEFORE         │
   │  anything is enabled. Declares exactly what may be read,      │
   │  from where, until when.                                      │
   └───────────────────────────┬──────────────────────────────────┘
                               │ deployed alongside the binary
                               ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  FIELDLINK POLICY ENGINE                                      │
   │  Holds ONLY the pinned public key (/etc/fieldlink/trusted.pub)│
   │  Verifies signature + expiry + agent binding + constraints    │
   │  on EVERY tools/call. Not once at load.                       │
   └──────────────────────────────────────────────────────────────┘

   ┌──────────────────────────────────────────────────────────────┐
   │  MCP CLIENT / MODEL                                           │
   │  Can invoke. Cannot amend. Holds no key material.             │
   └──────────────────────────────────────────────────────────────┘
```

The claim this supports, stated for the README:

> Compromising the AI, the MCP client, or the machine's network position does
> not widen what FieldLink will do. Widening requires the offline signing key.

### 6.3 Grant format

```yaml
# grant.yaml   — signed into grant.yaml.sig
version: 1
grant_id: 01J9Z8Q7K3M4N5P6R7S8T9V0W1     # ULID
agent_id: fieldlink-plant2-gw01           # binds to one installation
issued_at: 2026-09-01T00:00:00Z
expires_at: 2026-12-01T00:00:00Z          # mandatory; 180d maximum
issuer: security@example.com

capabilities:
  - capability: fs.read
    constraints:
      paths:     ["/mnt/exports/**/*.csv"]   # matched AFTER symlink resolution
      max_bytes: 10485760

  - capability: db.query
    constraints:
      datasources: ["erp_readonly"]
      max_rows:    5000

  - capability: device.modbus.read
    constraints:
      devices:   ["line2-plc"]
      registers: ["boiler_temp", "line_speed", "fault_code"]

  - capability: http.request
    constraints:
      cidrs:   ["10.20.0.0/16"]
      methods: ["GET"]
```

### 6.4 Verification rules

- **Algorithm** — Ed25519 (RFC 8032).
- **Canonicalisation** — RFC 8785 (JSON Canonicalisation Scheme), with the
  signature computed over `"fieldlink-grant-v1:" || jcs(document)`. The domain
  separator prevents a signature from this scheme being replayed into another.
- **Pinning** — the public key is installed to `/etc/fieldlink/trusted.pub`, and
  its fingerprint is logged at every startup. A changed fingerprint produces a
  loud warning, never a silent reload.
- **Per-request verification** — a cached "grant is valid" boolean is precisely
  the bug this design exists to prevent.
- **Mandatory expiry** — a document without `expires_at`, or with one more than
  180 days out, is rejected by the parser.
- **Agent binding** — `agent_id` must match local config, so a grant lifted from
  one site cannot be replayed at another.
- **Fail closed** — missing, malformed, expired or unverifiable grant means the
  MCP server starts, advertises **zero** tools and zero resources, and returns a
  clear reason on any call. It does not refuse to start; an operator needs to be
  able to connect and see why.
- **Live expiry** — when a grant expires mid-session, FieldLink emits
  `notifications/tools/list_changed` and `notifications/resources/list_changed`,
  then serves an empty list.

### 6.5 Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Prompt injection widens agent behaviour | Grant is not model-controlled; unauthorised tools are never advertised | Model can still misuse *authorised* reads |
| Compromised or malicious MCP client | Client holds no key material and cannot amend the grant | Client sees everything the grant permits |
| SSRF via `http.request` | Post-resolution CIDR check, metadata endpoints hard-blocked, no cross-host redirects | DNS rebinding only partly mitigated by re-resolution |
| DNS rebinding against HTTP transport | Origin validation, localhost bind by default, bearer token when remote | Misconfigured `--allow-remote` deployments |
| Path traversal via `fs.read` | Symlinks resolved before glob evaluation; `..` rejected | Bind-mount confusion on unusual filesystems |
| SQL injection via `db.query` | Statement-type allow-list, bound parameters, read-only DB user | A too-permissive DB user defeats this |
| Credential theft from host | Secrets age-encrypted; key from systemd-creds or TPM where present | Root on the host defeats everything |
| Audit tampering | SHA-256 hash chain; `fieldlink audit verify` | Root can truncate — the chain makes it *detectable*, not impossible |
| Supply chain | Reproducible builds, SBOM, cosign signatures, checksums in release notes | Standard open-source exposure |
| Physical harm via device write | Write function codes not implemented | None from this vector in v0.1 |

The residual column is deliberately filled in. A security page claiming no
residual risk reads as naive or dishonest to exactly the audience this project
needs to convince.

---

## 7. Internal request path

```
  tools/call { name: "read_modbus", arguments: { device, register } }
        │
        ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ 1  MCP LAYER                                                 │
  │    · JSON-RPC parse, protocol version check                  │
  │    · resolve tool name → capability id                       │
  │    · validate arguments against inputSchema                  │
  └──────────────────────────────┬───────────────────────────────┘
                                 ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ 2  POLICY ENGINE          ◄── THE TRUST BOUNDARY             │
  │    a. verify grant signature (Ed25519, JCS, pinned key)      │
  │    b. check expiry and agent_id binding                      │
  │    c. is this capability present in the grant?               │
  │    d. do the arguments satisfy its constraints?              │
  │       · fs      → resolve symlinks, then glob match          │
  │       · http    → resolve DNS, then CIDR match               │
  │       · device  → named register present in allow-list?      │
  │       · db      → named datasource present? statement type?  │
  │    DENY ──────────────────────────────► audit(deny) ─► isError│
  └──────────────────────────────┬───────────────────────────────┘
                                 ▼ allow
  ┌──────────────────────────────────────────────────────────────┐
  │ 3  EXECUTOR                                                  │
  │    · acquire per-device mutex (serial/RTU buses)             │
  │    · open pooled connection, apply timeout                   │
  │    · perform the read                                        │
  │    · decode via register map / row typing                    │
  └──────────────────────────────┬───────────────────────────────┘
                                 ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ 4  AUDIT                                                     │
  │    · append record, chain to prev_hash                       │
  │    · parameters stored as DIGEST, never in the clear         │
  └──────────────────────────────┬───────────────────────────────┘
                                 ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ 5  RESPONSE ASSEMBLY                                         │
  │    · content[] (human-readable) + structuredContent (typed)  │
  │    · isError on execution failure, never a JSON-RPC error    │
  └──────────────────────────────────────────────────────────────┘
```

Steps 2 and 4 run on every call without exception, including calls that fail at
step 3.

---

## 8. Audit log

One JSON object per line, append-only, hash-chained.

```json
{
  "seq": 1042,
  "ts": "2026-09-14T08:31:02.441Z",
  "agent_id": "fieldlink-plant2-gw01",
  "grant_id": "01J9Z8Q7K3M4N5P6R7S8T9V0W1",
  "session_id": "01J9ZA1B2C3D4E5F6G7H8J9K0L",
  "capability": "device.modbus.read",
  "tool": "read_modbus",
  "decision": "allow",
  "params_digest": "sha256:9f2b…",
  "result": { "status": "ok", "bytes": 24, "rows": null },
  "duration_ms": 31,
  "prev_hash": "sha256:1c4e…",
  "hash": "sha256:7a0d…"
}
```

- `hash = SHA256( jcs(record_without_hash) || prev_hash )`.
- Parameters are recorded as a digest, not in the clear. An audit log that
  quietly accumulates plaintext ERP queries becomes its own data-protection problem.
- Denials are recorded with the same weight as allows, including which constraint
  failed.
- `fieldlink audit verify` walks the chain and reports the first break.
- `fieldlink audit export --format cef` produces SIEM-ingestible output.

---

## 9. Configuration

Two files, with different owners. That separation is what makes security review
possible: the operator can change how things connect without changing what may
be read.

```yaml
# /etc/fieldlink/config.yaml          — owned by the operator
agent_id: fieldlink-plant2-gw01

server:
  transport: stdio                    # or: http
  http:
    bind: 127.0.0.1:8765
    allowed_origins: ["http://localhost:*"]
    # remote binding additionally requires --allow-remote and a bearer token

grant:
  path:        /etc/fieldlink/grant.yaml
  trusted_key: /etc/fieldlink/trusted.pub

audit:
  path:      /var/log/fieldlink/audit.jsonl
  rotate_mb: 128

datasources:
  erp_readonly:
    driver:  mssql
    dsn_env: FIELDLINK_ERP_DSN        # never inline
    max_open_conns: 4

devices:
  line2-plc:
    protocol: modbus-tcp
    address:  10.20.4.11:502
    unit_id:  1
    timeout:  2s
    registers:
      boiler_temp:
        { fc: 3, address: 40021, type: float32, word_order: swapped,
          scale: 0.1, unit: "degC", range: [0, 150] }
      line_speed:
        { fc: 3, address: 40033, type: uint16, scale: 1, unit: "m/min" }
      fault_code:
        { fc: 3, address: 40040, type: uint16, lookup: "faults.yaml" }
```

---

## 10. Demo mode

`fieldlink demo` does five things in one command:

1. Starts an in-process Modbus TCP simulator on `127.0.0.1:5020` with a
   realistic register map — a boiler temperature that drifts, a line speed, an
   occasional fault code.
2. Generates a throwaway Ed25519 keypair.
3. Signs a demo grant covering the simulated device.
4. Starts the MCP server.
5. Prints the exact client config block to paste into Claude Code or Cursor.

This is a headline feature, not a convenience. **The biggest barrier to adoption
is that evaluators do not own a PLC.** Without demo mode, the reachable audience
is limited to people with industrial hardware on their desk. With it, any curious
engineer reproduces the README demo in under a minute — and time-to-first-success
is the variable that governs whether an open-source project spreads.

---

## 11. Technology choices

| Choice | Rationale | Rejected alternative |
|---|---|---|
| **Go** | Static binary, trivial cross-compile to armv7/arm64, no runtime on the host. The only language acceptable across workstation, server and embedded tiers. | Rust — better footprint, slower solo velocity. Python — needs a runtime no plant will install on a production host. |
| Official Go MCP SDK, or `mark3labs/mcp-go` | Protocol implementation; choose whichever is better maintained at build time | Hand-rolled JSON-RPC — pointless surface area |
| `simonvetter/modbus` | Mature, TCP and RTU, cgo-free | `goburrow/modbus` — less active |
| `gopcua/opcua` | De facto Go OPC-UA implementation | Wrapping open62541 — reintroduces cgo, kills static builds |
| `hirochachacha/go-smb2` | Pure-Go SMB2, no kernel mount, no root required | Mounting shares — needs privileges FieldLink should not hold |
| `microsoft/go-mssqldb`, `sijms/go-ora`, `jackc/pgx` | Pure-Go drivers across all three databases | `godror` — requires Oracle Instant Client on the host |
| `bbolt` | Embedded store for the replay/nonce cache | SQLite — cgo, or a heavier pure-Go port |
| `filippo.io/age` | Small, auditable secret encryption | Full Vault integration — wrong weight class for v0.1 |

**`CGO_ENABLED=0` is non-negotiable.** It is the property that lets one binary
run on Yocto, Alpine, OpenWrt and a twelve-year-old CentOS box alike. Every
dependency above was selected to preserve it.

---

## 12. Non-functional targets

| Property | Target | Why this number |
|---|---|---|
| Binary size | < 20 MB stripped | Fits constrained edge flash |
| RSS at idle | < 30 MB | Industrial gateways commonly have 256 MB–1 GB total |
| Cold start | < 200 ms | stdio transport launches per client session |
| Grant verification | < 1 ms | Runs on every single call |
| Modbus read | < 50 ms on a local segment | Dominated by the PLC, not by us |
| Concurrent tool calls | 8, configurable | Serial and RTU devices require strict per-bus serialisation |
| Platforms | linux/amd64, linux/arm64, linux/arm/v7 | Windows in v0.2 |

---

## 13. Repository layout

```
fieldlink/
├── README.md                 # GIF above the fold; demo command in the first 10 lines
├── SECURITY.md               # threat model + disclosure address
├── LICENSE                   # Apache-2.0
├── cmd/fieldlink/            # cobra CLI: serve · demo · grant · audit
├── internal/
│   ├── mcp/                  # server, transports, tool/resource/prompt registration
│   ├── policy/               # grant parse, Ed25519 verify, constraint matching
│   ├── exec/
│   │   ├── fs/  db/  httpx/
│   │   └── device/           # modbus/  opcua/
│   ├── audit/                # hash chain, verify, CEF export
│   ├── secrets/              # age · systemd-creds · TPM
│   └── simulator/            # demo mode
├── examples/
│   ├── grants/               # signed grants per scenario
│   └── clients/              # Claude Code, Cursor, n8n config snippets
├── docs/
│   ├── quickstart.md
│   ├── trust-model.md        # written for security teams, not developers
│   └── register-maps.md
└── .github/workflows/        # cross-compile matrix, cosign, SBOM, release
```

---

## 14. Build plan

Weeks are evenings and weekends, not full-time.

| Week | Deliverable | Done when |
|---|---|---|
| 1 | Skeleton, config, MCP server layer, `fs.read` / `fs.list` | Claude Code lists and reads a file through FieldLink |
| 2 | Policy engine, grant format, Ed25519 verify, `fieldlink grant sign` | An unsigned grant yields zero advertised tools |
| 3 | `device.modbus.read`, register maps, simulator, `demo` | `fieldlink demo` works on a clean machine with no hardware |
| 4 | `db.query`, `http.request`, resources, prompts, audit chain | End-to-end on a real Pi against a real Modbus device; demo GIF recorded |
| 5 | Docs, SECURITY.md, CI cross-compile matrix, signed release | One-line install works on Pi, amd64 and Alpine |
| 6 | **Public** — repo live, Show HN, r/PLC, r/homeassistant, MCP registry | — |
| 7–8 | `device.opcua.read`, SMB executor, issue triage | First external issue closed |
| 9–12 | Twenty conversations; one paid pilot offered | See §14.1 |

### 14.1 Kill criteria — fixed now, in writing

At day 90, if **none** of the following hold, the thesis is wrong and the project
stops:

- ≥ 100 GitHub stars
- ≥ 3 external issues or PRs from people who are not the author
- ≥ 1 person who has stated in writing that they would pay for something here

These are written down before launch deliberately. Afterwards, every number looks
like it might turn around next month.

---

## 15. Roadmap beyond v0.1

Only after v0.1 shows evidence of use:

- **v0.2** — Windows agent (signed MSI), OPC-UA subscriptions, SMB executor
  hardening, remote transport back to a coordinating service.
- **v0.3** — fleet enrolment, multi-agent grant distribution, operational console.
- **v1.0** — write capabilities, behind a physical-interlock design and a real
  customer safety case. Not before.

Any commercial layer is fleet management and support — never the agent itself.
The agent remaining Apache-2.0 and genuinely useful standalone is what makes the
distribution work at all.

---

## 16. Open risks

**Technical**

1. **Register-map authoring is the real UX problem.** Nobody wants to hand-write
   the map, and getting it wrong produces confidently wrong readings — the worst
   failure mode available. Mitigation: import from the CSV exports most SCADA
   tools already produce. Unsolved for v0.1.
2. **OPC-UA security policies are a swamp.** Certificate handling is inconsistent
   across vendor implementations. Budget more time than seems reasonable.
3. **Serial/RTU concurrency bugs look like hardware faults**, which makes them
   very expensive to diagnose remotely. The per-device mutex must be right first time.
4. **Pure-Go SMB2 is less battle-tested** than a kernel mount. Accepted in
   exchange for requiring no privileges.

**Strategic**

5. **The audience may not overlap.** OT engineers are conservative and are not
   reading AI tooling announcements. This is the core distribution bet and it is
   unproven.
6. **A gateway project or a model vendor could ship device executors.** The
   defence is the offline-grant trust model plus industrial credibility, neither
   of which is a durable moat. Speed matters more than architecture here.
7. **Read-only caps the value ceiling.** Some buyers will want writes and walk
   away. That is the correct trade for v0.1.

**Non-technical**

8. **Employment IP assignment must be resolved before the first public commit.**
   It is the only item on this list that can retroactively invalidate everything
   above.

---

## Appendix A — Capability and constraint reference

| Capability | Grant constraints | Enforcement |
|---|---|---|
| `fs.read` | `paths[]` (doublestar glob), `max_bytes` | Match after symlink resolution |
| `fs.list` | `paths[]`, `recursive` | Match after symlink resolution |
| `db.query` | `datasources[]`, `max_rows` | Named lookup + statement-type parse |
| `http.request` | `cidrs[]`, `methods[]` | Match after DNS resolution, re-checked per redirect |
| `device.modbus.read` | `devices[]`, `registers[]` | Named register lookup; FC restricted to 1–4 |
| `device.opcua.read` | `endpoints[]`, `node_prefixes[]` | Node ID prefix match |

## Appendix B — MCP methods implemented

| Method | Notes |
|---|---|
| `initialize` / `notifications/initialized` | Capability negotiation; `instructions` carries domain rules |
| `tools/list`, `tools/call` | Tool set derived from the grant |
| `notifications/tools/list_changed` | Emitted on grant expiry or reload |
| `resources/list`, `resources/read` | Register maps, schemas, redacted grant |
| `notifications/resources/list_changed` | Emitted on grant or config change |
| `prompts/list`, `prompts/get` | Three diagnostic workflows |
| `logging/setLevel`, `notifications/message` | Operator-facing diagnostics |
| `notifications/progress` | Long `db.query` and multi-node OPC-UA reads |
| `ping` | Liveness |
| *not implemented* | `sampling/*`, `roots/*`, `completion/*`, resource `subscribe` |

## Appendix C — Standards referenced

| Standard | Use |
|---|---|
| Model Context Protocol | Tool, resource and prompt exposure |
| JSON-RPC 2.0 | Wire format for MCP |
| RFC 8032 | Ed25519 signatures |
| RFC 8785 (JCS) | Canonical JSON for signing and audit hashing |
| Modbus Application Protocol v1.1b3 | Function codes 1–4 |
| OPC UA Part 4 / Part 6 | Services and mappings |
| SPDX | SBOM published per release |
| CEF | Audit export for SIEM ingestion |
