# Moving this to Claude Code

## 1. Install

```bash
curl -fsSL https://claude.ai/install.sh | bash
claude --version
claude doctor
```

This is the native installer — no Node.js, no Docker, no other runtime. The old
`npm install -g @anthropic-ai/claude-code` path still works but is deprecated. Never use
`sudo` with it.

Claude Code needs a paid plan (Pro, Max, Team, Enterprise, or a Console account billed at
API rates). The free claude.ai plan does not include it.

Current docs: https://code.claude.com/docs/en/setup

## 2. Set up the folder

Download everything from this session into one directory:

```
fieldlink/
├── CLAUDE.md          ← project context, read automatically on every session
├── README.md
├── SECURITY.md
├── LICENSE
├── PUSH.md
├── .gitignore
└── docs/
    └── design.md      ← the full technical design
```

`CLAUDE.md` is the important one. Claude Code reads it at the start of every session, so
the constraints (no writes, `CGO_ENABLED=0`, per-call policy checks, scope discipline)
carry over without you re-explaining them.

## 3. Start

```bash
cd fieldlink
claude
```

## 4. First prompt

Paste this:

> Read CLAUDE.md and docs/design.md, then confirm the plan for Week 1 before writing any
> code. Week 1 is: Go module skeleton, config loading, the MCP server layer over stdio, and
> the `fs.read` and `fs.list` executors. No policy engine yet — stub it to allow-all with a
> loud TODO, because the real one lands in Week 2 and I want the interface right first.
>
> Before you start, check which Go MCP SDK is currently better maintained — the official one
> or mark3labs/mcp-go — and tell me which you picked and why.
>
> Done means: I can add fieldlink to Claude Code's own MCP config and read a file through it.

## 5. Then create the repo

Once there's something that runs, ask Claude Code to `git init` and push. It has real git
access, so it can do the whole thing — but see PUSH.md first, and resolve the IP assignment
question before anything goes public.

## What's already decided

Don't relitigate these in the new session; they're in CLAUDE.md and docs/design.md:

- MCP server, not a cloud agent — collapses setup to ~60 seconds, which is what governs
  open-source adoption
- Read-only, writes not implemented rather than disabled
- Offline-signed Ed25519 grants, verified per call
- Go, `CGO_ENABLED=0`, linux/amd64 + arm64 + armv7
- Six capabilities, no more
- Kill criteria at day 90: 100 stars, 3 external contributors, 1 person who says in writing
  they'd pay. Zero of three means stop.
