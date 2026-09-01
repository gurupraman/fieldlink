# FieldLink

**An MCP server for systems that have no API.**

Modbus, OPC-UA, SMB shares, on-prem SQL. One static Go binary. No Docker, no Kubernetes, no cloud account.

<p align="center">
  <a href="#quickstart"><img alt="Quickstart" src="https://img.shields.io/badge/quickstart-60_seconds-0f766e"></a>
  <a href="#read-only-by-design"><img alt="Read only" src="https://img.shields.io/badge/writes-not_implemented-d97706"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache_2.0-blue"></a>
  <a href="#status"><img alt="Status" src="https://img.shields.io/badge/status-pre--alpha-lightgrey"></a>
</p>

---

> [!WARNING]
> **Status: pre-alpha.** The design is complete and the build is in progress. Nothing here is
> production-ready yet. Watch the repo or open an issue if you want to be told when it is.
> *(Delete this block at the first tagged release.)*

## The problem

Your AI agent can reach anything with a REST API. It cannot reach the CSV a machine drops on
an SMB share, the holding register on a line controller, or the read-only view on an ERP
database that has no route to the internet.

Those systems will never get REST APIs, and nobody is installing Docker on a factory gateway
to work around it.

FieldLink runs *on that network*, speaks those protocols, and presents them to any MCP client
as tools — under a permission model the AI cannot alter.

## Quickstart

No hardware required. `fieldlink demo` starts a simulated PLC, signs a throwaway grant, and
prints the config block to paste.

No tagged release exists yet, so there's no install script or prebuilt binary — build from
source (requires Go 1.24+):

```bash
git clone https://github.com/gurupraman/fieldlink.git
cd fieldlink && go build -o fieldlink ./cmd/fieldlink
./fieldlink demo
```

Then add it to your MCP client:

```json
{
  "mcpServers": {
    "fieldlink": { "command": "fieldlink", "args": ["serve", "--config", "~/.fieldlink/demo.yaml"] }
  }
}
```

(Use the full path to the binary you just built, or put it on your `PATH`.)

Ask your agent: *"What's the boiler temperature on line 2?"*

<details>
<summary>Other install methods</summary>

```bash
# Go, without cloning first — resolves to the latest commit on main
# since no versioned release has been tagged yet
go install github.com/gurupraman/fieldlink/cmd/fieldlink@latest
```

Once a version is tagged, CI cross-compiles `linux/amd64`, `linux/arm64`, `linux/arm/v7`, and
`windows/amd64`, and publishes checksums, an SBOM, and a cosign signature for each — see
[Releases](https://github.com/gurupraman/fieldlink/releases). Nothing has been tagged yet, so
that page is currently empty.
</details>

## What it reaches

| System | Tool | Notes |
|---|---|---|
| Modbus TCP / RTU | `read_modbus` | Function codes 1–4. Symbolic register names from a register map. |
| OPC-UA | `read_opcua` | Anonymous and username auth. Reads node IDs you already know — no browse/discovery tool yet. |
| SMB shares | `read_file`, `list_directory` | Pure-Go SMB2. No kernel mount, no root. Via `smb://<share-name>/<path>`. |
| MSSQL, Oracle, Postgres | `query_database` | Named datasources only. `SELECT`/`WITH` only. |
| Internal HTTP | `call_internal_http` | GET and HEAD, restricted to allow-listed CIDRs. |

It also exposes register maps, fault-code tables and database schemas as MCP **resources**, so
the model can ask for `boiler_temp` instead of guessing at "holding register 40021, swapped
word order, divide by ten."

## Read-only by design

**FieldLink does not write. Anywhere. The write function codes are not implemented — not gated,
not behind a flag, not present in the codebase.**

A bad file write corrupts a file. A bad Modbus coil write moves a physical actuator. There is a
short path from a prompt injection buried in a maintenance PDF to a machine starting while
somebody's hands are inside it, and that path should not exist in software that has not been
through a safety review.

Writes belong behind an interlock this software does not control. That's a v1.0 conversation
with a customer who has a safety case, not a checkbox.

## Trust model

Most agent tooling lets the thing that *issues* commands also decide what's *permitted*.
Compromise the client — or inject the model — and permissions widen quietly.

FieldLink separates the two. What it may do is declared in a grant signed by an **offline
Ed25519 key** that never touches the FieldLink host. The binary holds only the pinned public
key and verifies **every single call** locally.

```yaml
# grant.yaml — signed offline, reviewable by a security team before anything is enabled
capabilities:
  - capability: device.modbus.read
    constraints:
      devices:   ["line2-plc"]
      registers: ["boiler_temp", "line_speed", "fault_code"]
  - capability: fs.read
    constraints:
      paths: ["/mnt/exports/**/*.csv"]
expires_at: 2026-12-01T00:00:00Z    # mandatory, 180 days maximum
```

> Compromising the AI, the MCP client, or the machine's network position does not widen what
> FieldLink will do. Widening it requires the offline signing key.

Capabilities absent from the grant never appear in `tools/list`, so the model never sees a tool
it can't use. No grant means zero tools advertised and a clear reason on every call — it fails
closed, loudly.

Full threat model, including residual risks, is in [SECURITY.md](SECURITY.md).

## Where it fits

FieldLink is a **tool provider**, not a gateway. It's complementary to the projects below, and
happily runs behind one:

| | What they do | What FieldLink adds |
|---|---|---|
| Bifrost, agentgateway, MCPX, MetaMCP | Aggregate and route existing MCP servers | Those servers have to exist first. FieldLink *is* the server for systems that have none. |
| mcp-firewall | Policy and audit around MCP traffic | Put it in front of FieldLink. They compose. |
| UiPath, Adopt AI, SpaceFlow | On-prem agent platforms | Those need Kubernetes or a cloud account. This is one binary and a config file. |

## Audit

Every call — allowed or denied — appends to a SHA-256 hash-chained JSONL log. Parameters are
stored as digests, never in the clear, so the audit trail doesn't quietly become its own data
protection problem.

```bash
fieldlink audit verify                          # walk the chain, report the first break
fieldlink audit export --format cef > siem.log  # SIEM-ingestible
```

## Platforms

`linux/amd64` · `linux/arm64` · `linux/arm/v7` · `windows/amd64` — built `CGO_ENABLED=0`, no
runtime dependency. The Linux binaries run on Yocto, Alpine, OpenWrt, and hardware old enough
to vote. Windows works (tested in CI on a real Windows runner) but isn't packaged yet — no
signed installer, no MSI, just the raw `.exe`, and Windows SmartScreen will flag it.

Currently ~30 MB stripped, over the <20 MB target — the tradeoff of shipping five protocol
integrations (Modbus, OPC-UA, SMB, three SQL dialects) rather than deferring most of them
past v0.1.

## Documentation

- [Quickstart](docs/quickstart.md)
- [Trust model](docs/trust-model.md) — written for security teams, not developers
- [Register maps](docs/register-maps.md)
- [Full technical design](docs/design.md)

## Contributing

Issues and PRs welcome, especially:

- **Register maps** for real equipment — the most useful thing you can contribute
- Vendor-specific OPC-UA quirks
- Reports of anything that behaves oddly on unusual hardware

Please don't open PRs adding write capabilities. See [Read-only by design](#read-only-by-design).

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Please don't file them
as public issues.

## License

Apache-2.0. See [LICENSE](LICENSE).
