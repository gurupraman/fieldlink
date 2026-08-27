# Security Policy

FieldLink runs inside networks that reach physical equipment. Please treat findings
accordingly.

## Reporting a vulnerability

Email **security@<your-domain>** — please do not open a public issue.

Include what you can: affected version, capability involved, and a reproduction. Expect an
acknowledgement within 72 hours and an assessment within 7 days.

## Design posture

**No writes.** Modbus write function codes (5, 6, 15, 16) are not implemented. Not gated, not
flagged — absent from the codebase. `fs.write`, `db.exec` and `proc.exec` likewise. A bad write
to industrial equipment moves a physical actuator, and that path should not exist in software
that has not been through a safety review.

**Offline-signed grants.** What FieldLink may do is declared in a grant signed by an Ed25519
key that never touches the FieldLink host. The binary holds only the pinned public key and
verifies every call locally — not once at load.

**Fails closed.** Missing, malformed, expired or unverifiable grant means zero tools
advertised and a clear reason on every call.

## Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Prompt injection widens agent behaviour | Grant is not model-controlled; unauthorised tools never advertised | Model can still misuse *authorised* reads |
| Compromised MCP client | Client holds no key material, cannot amend the grant | Client sees everything the grant permits |
| SSRF via `call_internal_http` | Post-resolution CIDR check; metadata endpoints hard-blocked; no cross-host redirects | DNS rebinding only partly mitigated |
| DNS rebinding (HTTP transport) | Origin validation; localhost bind by default; bearer token when remote | Misconfigured `--allow-remote` deployments |
| Path traversal | Symlinks resolved before glob evaluation; `..` rejected | Bind-mount confusion on unusual filesystems |
| SQL injection | Statement-type allow-list, bound parameters | A too-permissive DB user defeats this — **use a read-only account** |
| Credential theft from host | Secrets age-encrypted; key from systemd-creds or TPM | Root on the host defeats everything |
| Audit tampering | SHA-256 hash chain; `fieldlink audit verify` | Root can truncate — the chain makes it detectable, not impossible |
| Supply chain | Reproducible builds, SBOM, cosign signatures | Standard open-source exposure |

The residual column is filled in deliberately. Anyone claiming zero residual risk in software
like this is either mistaken or selling something.

## Supported versions

Pre-alpha. No version is supported for production use yet.
