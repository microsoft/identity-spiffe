# CLAUDE.md — Infrastructure (Bicep)

> All Azure infrastructure-as-code for the AIM Prototype Platform. Deployed via `azd provision` (Step 1 of deploy.sh).

## What Gets Deployed

| Resource | Purpose |
|----------|---------|
| Container Apps Environment | Hosts all four agent Container Apps |
| Azure Container Registry | Stores spiffe-proxy and agent images |
| Azure VM | SPIRE Server (needs IMDS access — Container Apps doesn't expose it) |
| Virtual Network | Internal networking between Container Apps and VM |
| Managed Identities | AcrPull for Container Apps, VM identity for SPIRE |

## Key Files

```
infra/
├── main.bicep                   ← Orchestrator — calls all modules
├── main.parameters.bicepparam   ← azd parameter injection
└── modules/
    ├── acr.bicep                ← Azure Container Registry
    ├── container-app.bicep      ← Container App definitions (base template)
    ├── container-app-phase2.bicep ← Phase 2 Container App with SPIFFE sidecar params
    ├── container-apps-env.bicep ← Container Apps Environment
    ├── spire-server.bicep       ← SPIRE Server (base module)
    ├── spire-server-aci.bicep   ← SPIRE Server on ACI (deprecated — no IMDS)
    └── spire-server-vm.bicep    ← SPIRE Server on VM (active — full IMDS access)
```

## Important Notes

- **Container App definitions in Bicep are templates only.** deploy.sh overrides container specs in Step 6 with the full sidecar configuration. Bicep creates the Container App resource; deploy.sh configures the actual containers.
- **AcrPull role assignment** has a propagation delay (~60s). deploy.sh waits after provisioning.
- **VM NSG** must allow inbound TCP 8081 from the Container Apps subnet (SPIRE Agent → Server).
- **Region: westus** — configured in `main.bicep` as the default location.
- **Foundry resources removed** — Cognitive Services, Foundry account/project, and model deployments were removed in ADR-009. No Foundry infrastructure remains. The stale `main.json` compiled ARM template was also removed.

## Modifying Infrastructure

1. Edit Bicep files
2. Run `azd provision` (only provisions infra, doesn't deploy apps)
3. Then run the remaining deploy.sh steps (3-6) for application deployment

Never edit Container App container specs in Bicep — deploy.sh manages the full container configuration to avoid the multi-container reset bug (Learning #3).
