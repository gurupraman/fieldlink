# Quickstart

No hardware required. This walks through `fieldlink demo`: a simulated
Modbus PLC, a throwaway signed grant, and a real MCP tool call from Claude
Code.

## 1. Build

Tagged releases publish signed binaries for `linux/amd64`, `linux/arm64`,
`linux/arm/v7`, and `windows/amd64` — see the repo's Releases page. Until
there's a tagged release, build from source:

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

## Remote deployment: MCP client and binary on different machines

Everything above uses stdio: the MCP client *spawns* `fieldlink serve` as a
local child process, so client and binary have to be on the same machine.
That's not always what you want — a common real shape is `fieldlink`
running on a gateway PC on the plant network (Windows or Linux) while the
MCP client is an engineer's laptop, or a cloud-hosted agent, somewhere else
entirely. stdio can't reach across that gap. HTTP can.

### 1. Pick an auth mode

Three options, all enforced the same way: `--allow-remote` refuses to start
unless exactly one is configured — there is no unauthenticated remote mode,
and the three are mutually exclusive.

**OAuth against your own IdP (recommended if you already have one).**
FieldLink acts as an OAuth 2.1 *resource server* — it validates access
tokens your existing identity provider (Okta, Azure AD, Auth0, Keycloak,
anything with standard OIDC discovery) already issues. It does not run its
own auth server or issue tokens itself, and every deployment points at
whatever IdP *that* operator already has — FieldLink never hosts a shared
one.

```yaml
server:
  transport: http
  http:
    bind: 0.0.0.0:8765
    tls:
      cert_file: /etc/fieldlink/tls/server.crt
      key_file: /etc/fieldlink/tls/server.key
    oauth:
      issuer_url: "https://your-tenant.okta.com"   # or Azure AD / Auth0 / Keycloak
      audience: "fieldlink-plant2-gw01"
      required_scopes: ["fieldlink:read"]
```

Compliant clients discover how to authenticate automatically via
`GET /.well-known/oauth-protected-resource` (RFC 9728) — no manually
copy-pasted header on the client side.

**Built-in local issuer (no external IdP at all).** FieldLink issues its
own short-lived OAuth access tokens via the client-credentials grant (RFC
6749 §4.4) to a static, config-defined client list. This is deliberately
narrow — no user accounts, no login UI, no dynamic client registration —
but it's a real, standard-shaped OAuth flow: FieldLink generates and
persists its own signing key on first run, serves real discovery/JWKS
endpoints, and validates the tokens it issues through the exact same code
path used for an external IdP.

```yaml
server:
  transport: http
  http:
    bind: 0.0.0.0:8765
    tls:
      cert_file: /etc/fieldlink/tls/server.crt
      key_file: /etc/fieldlink/tls/server.key
    local_issuer:
      token_ttl: 15m
      clients:
        engineer-laptop:
          secret_env: FIELDLINK_CLIENT_SECRET
          scopes: ["fieldlink:read"]
```

A client obtains a token itself with a standard client-credentials POST:

```bash
curl -u "engineer-laptop:$FIELDLINK_CLIENT_SECRET" \
  -d grant_type=client_credentials -d scope=fieldlink:read \
  https://gateway-host:8765/oauth/token
```

...then uses the returned `access_token` as the bearer token for `/mcp`,
same as any OAuth flow. Revoking one client means removing its entry from
`clients:` (or rotating its `secret_env` value) and restarting — no other
client is affected, since each has its own secret.

**Static bearer token** — simplest, no IdP required, least individually
revocable (one shared secret for every client):

```yaml
server:
  transport: http
  http:
    bind: 0.0.0.0:8765
    tls:
      cert_file: /etc/fieldlink/tls/server.crt
      key_file: /etc/fieldlink/tls/server.key
    bearer_token_env: FIELDLINK_BEARER_TOKEN
```

`oauth` and `bearer_token_env` are mutually exclusive — `fieldlink` refuses
to start if both are set.

**TLS is not optional once you leave loopback.** Without it, the bearer
token or OAuth access token travels in cleartext over the network — anyone
on the path can read it. `fieldlink` logs a loud warning at startup if
you're remote-reachable without `tls` configured, but it doesn't stop you;
that check does.

### 2. Start it

**Same machine as the client**, or reachable only via an SSH tunnel /
existing VPN (recommended even with OAuth or TLS configured — one less
thing exposed to the whole network):

```bash
fieldlink serve --config config.yaml
```

If `bind` is left at the default `127.0.0.1:8765`, no `--allow-remote`, no
auth config, and no TLS are needed — nothing outside this host can reach it.

**Actually reachable from another machine:**

```bash
export FIELDLINK_BEARER_TOKEN="$(openssl rand -hex 32)"   # static-token mode only
fieldlink serve --config config.yaml --allow-remote
```

`--allow-remote` is required the moment `bind` isn't a loopback address —
this can't be worked around from config alone (it's a CLI flag, so a
leaked config file can't silently turn into a network-exposed server).
This widens exposure beyond the host, so it logs a loud warning on every
startup as a standing reminder.

### 3. Point the client at it

With OAuth, a spec-compliant client completes the auth flow itself once
pointed at the URL — check your client's docs for exact config shape. With
a static token:

```json
{
  "mcpServers": {
    "fieldlink": {
      "url": "https://gateway-host:8765/mcp",
      "headers": { "Authorization": "Bearer <the same token>" }
    }
  }
}
```

(Exact config key names for a URL-based MCP server vary by client. The
endpoint is always `/mcp`.)

### On Origin validation

`allowed_origins` entries must be **exact** origins
(`"https://your-editor.example.com"`) — no wildcards. This is a real
limitation of the Go standard library's CSRF protection this is built on,
not a FieldLink choice; a pattern like `"http://localhost:*"` will simply
never match anything. List every origin (including port) you actually use.

### Deploying the binary itself

The binary is the same static executable regardless of where it runs —
`linux/amd64`, `linux/arm64`, `linux/arm/v7` (Yocto, Alpine, OpenWrt,
anything that can exec the right architecture — no packaging step needed),
or `windows/amd64` (a raw `.exe`; no signed installer yet, so Windows
SmartScreen will warn on first run). Copy the binary, `config.yaml`, and
the grant files to the target machine; there's nothing else to install.

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
