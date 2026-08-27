# Quickstart

No hardware required. This walks through `fieldlink demo`: a simulated
Modbus PLC, a throwaway signed grant, and a real MCP tool call from Claude
Code.

## 1. Build

FieldLink isn't packaged yet (that lands in Week 5's release automation).
For now, build from source:

```bash
git clone https://github.com/gurupraman/fieldlink.git
cd fieldlink
go build -o fieldlink ./cmd/fieldlink
```

Requires Go 1.24+. The binary is static (`CGO_ENABLED=0` by default on most
platforms) — no runtime dependency.

## 2. Run the demo

```bash
./fieldlink demo
```

This does four things in one command:

1. Starts an in-process Modbus TCP simulator on `127.0.0.1:5020` — a
   drifting boiler temperature, a line speed, an occasional fault code.
2. Generates a throwaway Ed25519 keypair, entirely in memory. The private
   half is never written to disk and is discarded when the command exits.
3. Signs a grant covering exactly that simulated device
   (`device.modbus.read`, registers `boiler_temp`, `line_speed`,
   `fault_code`), and writes it, alongside the public key, to
   `~/.fieldlink/demo/`.
4. Writes `~/.fieldlink/demo.yaml` and prints the client config block.

Leave this command running — the simulator lives inside this process. The
config it prints points a *separate* `fieldlink serve` invocation at both
the simulator and the grant.

## 3. Add it to Claude Code

Paste the block `fieldlink demo` printed into your MCP client config
(`.mcp.json` for a project, or Claude Code's global config):

```json
{
  "mcpServers": {
    "fieldlink": { "command": "fieldlink", "args": ["serve", "--config", "/home/you/.fieldlink/demo.yaml"] }
  }
}
```

Then ask: *"What's the boiler temperature on line 2?"*

Claude Code spawns `fieldlink serve` as a subprocess, which connects back
to the simulator `fieldlink demo` is hosting. `serve` verifies the grant on
every single call — not once at startup — so even in the demo you're
exercising the real trust-boundary code path, not a shortcut.

## 4. What you should see

- `tools/list` advertises exactly one tool: `read_modbus`. The demo grant
  doesn't cover `fs.read`, `fs.list`, `http.request`, or `db.query`, so
  they never appear — this is the "capability absent from the grant is
  absent from tools/list" property, not a limitation of the demo.
- A `read_modbus` call for `boiler_temp` returns a decoded value in
  degrees C, the two raw register words, a `quality` field (`good` or
  `out_of_range`), and a timestamp.
- Stop `fieldlink demo` with Ctrl+C. `serve` will then fail to connect —
  that's expected, not a bug to report.

## Moving beyond the demo

Real usage means writing your own `config.yaml` (devices, datasources) and
having your security team sign a grant against your own trusted key —
covered in [register-maps.md](register-maps.md) and
[trust-model.md](trust-model.md) respectively. `fieldlink grant keygen`,
`sign`, and `verify` are the same commands `fieldlink demo` uses
internally; nothing about the demo path is a toy version of the real
mechanism.

## Troubleshooting

**`tools/list` is empty.** The grant is missing, expired, malformed, or
signed for a different `agent_id`. `fieldlink` fails closed by design —
check stderr, which logs the reason (never stdout, which would corrupt the
JSON-RPC stream). `fieldlink grant verify --grant ... --pubkey ...` checks
a grant standalone, outside the server.

**A call returns `isError: true` with a generic "Denied" message.** That's
intentional — denial messages never echo what the grant would otherwise
have allowed, so a compromised client can't use denials to map out scope
by probing. Check the server's stderr log for the specific reason.

**Connection refused to `127.0.0.1:5020`.** The `fieldlink demo` process
that hosts the simulator has stopped. It has to keep running in its own
terminal for the duration of your session.
