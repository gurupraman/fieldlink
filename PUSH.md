# Pushing this to GitHub

1. Create an empty repo at https://github.com/new
   - Name: `fieldlink`
   - Description: `MCP server for Modbus, OPC-UA, SMB shares and on-prem SQL — one Go binary, no Docker.`
   - Public. Do **not** add a README, .gitignore or licence (they're here already).

2. From this folder:

```bash
git init -b main
git add .
git commit -m "Initial commit: design, README, security policy"
git remote add origin git@github.com:<you>/fieldlink.git
git push -u origin main
```

3. In repo Settings → set the description and add topics:
   `mcp` `model-context-protocol` `modbus` `opc-ua` `industrial-automation`
   `iiot` `golang` `on-premise` `ai-agents` `scada`

   Topics are how people find this. Don't skip them.

## Before you push — check these

- [ ] Employment IP assignment reviewed. This is the gate; everything else is reversible.
- [ ] Replace `<you>` in README install commands with your GitHub handle.
- [ ] Replace `security@<your-domain>` in SECURITY.md.
- [ ] Full Apache-2.0 text in LICENSE.
- [ ] `docs/demo.gif` does not exist yet — the README image will show broken until you
      record it. Either record it first or drop that block until week 4.
