# Agent Instructions

This repository uses `CLAUDE.md` as shared guidance for AI coding agents and human contributors.

Before changing authentication, deployment, or authorization code, read:

1. `CLAUDE.md`
2. `docs/platform-learnings/agent-id-blueprints-and-users.md`
3. `docs/index.md`
4. `docs/runbooks/hard-won-learnings.md`

Security-sensitive paths must fail closed. Missing Graph data, missing tokens, invalid JWTs, or unreachable control planes must never be treated as safe.

All commits should include:

```text
Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
```
