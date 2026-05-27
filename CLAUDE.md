# CLAUDE.md — Identity Research for Agent Management Using SPIFFE

> Shared contributor and AI-agent guidance. Durable architecture and runbooks live in `docs/`.

## Non-Negotiables

- Read `docs/platform-learnings/agent-id-blueprints-and-users.md` before designing or changing any flow involving OAuth, OBO, Agent Identity, Agent Blueprints, Agent Users, MSAL, app registrations, redirect URIs, scopes, JWT validation, OIDC discovery, or PKCE.
- Security paths fail closed. Missing Graph data, missing tokens, invalid JWTs, or unreachable control planes must not be interpreted as safe.
- Test before committing. At minimum: Python syntax or relevant Python unit tests, relevant Go tests for `src/spiffe-proxy`, and `bash -n deploy.sh` when deployment scripts change.
- Trace both sides of every dependency. If code reads an environment variable, secret, route, or config value, confirm the writer/source exists in the same change.
- Do not use `azd deploy <service>` for agent services. Agent-side revisions consume join tokens and can break attestation. Use `./deploy.sh --skip-provision` or `./scripts/reattest.sh`.
- Use `./deploy.sh --portal-only` only for portal or Security Portal-only changes. Do not use it for sidecar, SPIRE, agent, or Entra bootstrap changes.
- Never use `az containerapp update --set-env-vars` on multi-container apps. It can remove sidecar containers. Export full YAML, edit it, and reimport it.
- Use `az vm run-command create --timeout-in-seconds`, never `az vm run-command invoke`.
- After a portal-only deploy, force a new portal revision because the image tag is reused and Azure Container Apps may not roll a revision automatically.

## Runtime Model

- Agent workloads run on Azure Container Apps with a Go `spiffe-proxy` sidecar and a SPIRE agent sidecar.
- SPIRE server runs on an Azure VM.
- `admin-control-plane` owns the public management path to protected `/mgmt/*` APIs.
- `isp-portal` and `securityportal-mock` are separate Container Apps with Entra browser sign-in.
- The portal backend is modular under `portal/app/`; `portal/server.py` is a thin wrapper.
- Cloud policy config persistence uses Azure Blob Storage through managed identity.
- Portal auth groups are shared tenant-wide: `Agent Management Administrators` and `Agent Management Viewers`.
- New environments default to environment-scoped Entra names for Blueprints, Agent Identities, FICs, and portal app registrations.

## Deploy Guidance

Common flows:

```bash
# Full environment deploy
./deploy.sh --new

# Existing environment, code or infra changed
./deploy.sh --skip-provision

# Portal-only changes
./deploy.sh --portal-only

# Full deploy with Google cross-cloud agent
./deploy.sh --new --google

# Add Google agent to an existing environment
./deploy.sh --skip-provision --google

# Full deploy with GitHub Actions agent
./deploy.sh --new --github

# Add GitHub agent to an existing environment
./deploy.sh --skip-provision --github

# Re-attest agents after a revision touched sidecars
./scripts/reattest.sh
```

Use `python3 scripts/test_agents.py` to validate the live enforcement matrix after deployment.

## High-Value Repo Areas

- `src/spiffe-proxy/`: transport, RBAC, JWT, and `/mgmt/*` enforcement
- `src/admin-control-plane/`: management proxy and agent discovery
- `portal/app/`: portal runtime, auth, clients, services, storage
- `scripts/entra_scope.py` and `scripts/lib/entra-scope.sh`: legacy vs scoped Entra naming
- `deploy.sh`: deployment contract, portal auth wiring, join-token, and attestation flow

## Cross-Cloud Notes

- Entra FIC `subject` for GCP service accounts must be the numeric unique ID, not the service account email.
- MSAL Python does not support FIC client assertions; cross-cloud token exchange uses raw HTTP.
- `spiffe-proxy` only has `server` and `agent-proxy` modes.
- `federated_policies` entries use exact `spiffe_id` values, not trust-domain-wide prefixes.
- The Google caller's `invoke_url` lives in the portal external-agent store, not in the RBAC policy YAML.
- Budget-backend ingress must be external TCP when Google federation is enabled; `deploy.sh --google` handles this.

## Docs Publishing

- MkDocs config: `mkdocs.yml`
- Local preview: `mkdocs serve`
- Workflow: `.github/workflows/docs.yml`
