# Trust model

This is written for whoever has to sign off on running FieldLink on a
network segment that reaches physical equipment, not for developers
integrating against it. It states what changes the security posture and
what doesn't, and it names residual risk explicitly rather than implying
there isn't any.

## The property this buys you

> Compromising the AI, the MCP client, or the machine's network position
> does not widen what FieldLink will do. Widening it requires the offline
> signing key.

This holds because FieldLink separates **who commands** (the MCP client,
the model) from **who authorizes** (a grant, signed offline). The client
can invoke tools the grant permits. It cannot amend the grant — it holds no
key material, and there is no API, flag, or environment variable that
grants a capability the signed document doesn't.

## What's in the trust boundary, and what isn't

**In the trust boundary — verified on every single call, not cached:**

- The grant's Ed25519 signature, against a public key pinned at
  `/etc/fieldlink/trusted.pub` (or wherever `config.yaml`'s
  `grant.trusted_key` points).
- The grant's expiry (`expires_at`), checked against wall-clock time.
- The grant's `agent_id`, checked against this installation's own
  `agent_id` in `config.yaml` — a grant signed for one site cannot be
  replayed at another.
- Per-capability constraints: which devices/registers/datasources/paths/
  CIDRs/methods the call's actual arguments match against.

`internal/policy.GrantEngine.Authorize` re-reads and re-verifies all of
this from disk on every call. There is no in-memory "grant is valid"
boolean anywhere in the codebase — that's a specific, named anti-pattern
this design exists to avoid, not an oversight to optimize away later.

**Outside the trust boundary — these do not widen access, by construction:**

- A prompt injection in a file, a database row, or an HTTP response
  FieldLink reads. The model can be tricked into *asking* for something,
  but the grant still gates whether that something is permitted.
- A compromised or fully malicious MCP client. It can call any tool the
  grant already permits, exactly as a well-behaved client could. It cannot
  call anything the grant doesn't permit, because it has no way to alter
  the grant or the pinned key.
- Network position. An attacker who can intercept traffic between the
  client and FieldLink (stdio makes this moot; the HTTP transport binds to
  localhost by default) still can't produce a validly-signed grant.

## What a signature review actually covers

A grant is a YAML document plus a detached signature
(`grant.yaml` + `grant.yaml.sig`), matching the pattern of a package
manifest plus a lockfile — human-readable, diffable, reviewable before
anything is enabled. `fieldlink grant verify` checks it independent of the
running server:

```bash
fieldlink grant verify --grant grant.yaml --pubkey trusted.pub
```

Under the hood: the YAML is parsed into a generic value, marshaled to JSON,
and canonicalized per RFC 8785 (JCS) — this is what makes the signature
deterministic regardless of key ordering or whitespace in how the YAML was
authored. The signed bytes are `"fieldlink-grant-v1:" || jcs(document)` —
the domain separator means a signature produced for this scheme can't be
replayed as valid for a different one, even if the underlying key is
reused elsewhere.

The private signing key is generated with `fieldlink grant keygen` and is
meant to live on a YubiKey, an HSM, or an air-gapped machine — never on the
FieldLink host. `fieldlink demo` generates a throwaway keypair entirely in
memory for its own grant and discards the private half when it exits, as a
concrete example of the discipline: even a five-minute demo doesn't put a
signing key on disk.

## Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Prompt injection widens agent behaviour | Grant is not model-controlled; unauthorised tools are never advertised | Model can still misuse *authorised* reads |
| Compromised or malicious MCP client | Client holds no key material and cannot amend the grant | Client sees everything the grant permits |
| SSRF via `http.request` | DNS resolved once, connection pinned to the resolved IP (not re-resolved by the HTTP client), metadata ranges hard-blocked ahead of the grant, redirects never followed automatically | A grant CIDR that's too broad still permits reaching everything inside it |
| Path traversal via `fs.read`/`fs.list` | Symlinks resolved before glob matching | Bind-mount confusion on unusual filesystems |
| SQL injection via `db.query` | Statement-type allow-list (SELECT/WITH only, no stacking), bound parameters | The allow-list is a tokenizer, not a full parser — it does not catch every side-effecting construct reachable from inside a single SELECT (a stored function call, for instance). The documented backstop is that **the database account FieldLink connects with must itself be read-only.** |
| Credential theft from host | Datasource connection strings come from an environment variable named in config, never inline | Root on the host, or read access to its environment, defeats this |
| Audit tampering | SHA-256 hash chain over every policy decision; `fieldlink audit verify` | Root can truncate the file — the chain makes that *detectable*, not impossible |
| Physical harm via device write | Write function codes are not implemented anywhere in the codebase | None from this vector — there is no code path to disable |

The residual column is filled in deliberately. A security document claiming
zero residual risk in software like this is either mistaken or selling
something.

## What live expiry does and doesn't do today

When a grant's `expires_at` passes, the *next* call against it is denied —
`Authorize` re-verifies from disk every time, so there's no window where an
expired grant keeps working until a restart. What's **not** yet
implemented is proactively pushing `notifications/tools/list_changed` the
moment a grant expires mid-session; the advertised `tools/list` can lag
briefly until the next list request. This is a known, deliberate scope cut
for v0.1, not a gap in enforcement.

## Reporting a finding

See [SECURITY.md](../SECURITY.md).
