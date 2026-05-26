# ADR-009: Remove Azure AI Foundry

**Status:** Accepted
**Date:** March 2026
**Deciders:** Project contributors

## Context

The PoC originally used Azure AI Foundry to host agent definitions and generate Foundry Agent IDs. These IDs were bridged into SPIFFE identities (`spiffe://aim.microsoft.com/foundry/<agent-name>/aid/<asst_...>`) and used throughout the enforcement stack.

Over time it became clear that Foundry provided **zero enforcement value**. All three real security layers — mTLS (transport), RBAC (application), and OAuth2 (token exchange) — work entirely through SPIFFE identities and Entra Agent Identity. Foundry was an extra dependency that:

- Added infrastructure complexity (Cognitive Services account, model deployment, SDK dependencies)
- Introduced deployment fragility (role propagation races on `agents/write`, soft-deleted account conflicts, API version sensitivity)
- Created confusion about what was actually enforcing security (the proxy + SPIRE, not Foundry)
- Required a `create-foundry-agents.py` script with its own retry logic and error handling

## Decision

**Remove Azure AI Foundry entirely.** Adopt the Entra Agent Identity Blueprint SPIFFE ID format as the canonical identity format.

SPIFFE ID format change:
```
Old: spiffe://aim.microsoft.com/foundry/<agent-name>/aid/<asst_...>
New: spiffe://aim.microsoft.com/ests/bp/<blueprint-oid>/aid/<agent-oid>
```

The `ests` namespace reflects ESTS (Entra STS) as the identity authority. The Blueprint OID is shared across all agents; the Agent OID is per-agent.

## Key Changes

- Deleted `infra/modules/foundry.bicep` and `scripts/create-foundry-agents.py`
- Replaced `FoundryAgentID` with `Name` field in RBAC `CallerPolicy`
- Rewrote `EnrichFromEnv()` to use Name-based env var lookup (`SPIFFE_PREFIX_<NAME>`, `ENTRA_ID_<NAME>`)
- Removed `X-SPIFFE-Foundry-Agent-ID` header from proxy chain
- Updated RBAC policy YAML to v3.0 format with `name` field
- Removed Foundry agent creation from `deploy.sh` (Step 2.5)
- Updated portal UI and server to remove all Foundry references
- Updated all test SPIFFE IDs to new format
- Cleaned up `teardown.sh`, `add/remove-demo-agent.sh` scripts

Net result: **-597 lines of code.**

## Rationale

1. **Foundry adds no security enforcement.** The SPIFFE proxy enforces mTLS and RBAC using SPIFFE IDs from SPIRE SVIDs. Foundry Agent IDs were simply embedded in the SPIFFE path — they didn't participate in any cryptographic verification or authorization decision.

2. **Entra Agent Identity is the real identity anchor.** The Entra Agent Identity Blueprint provides the authoritative identity for agents. Bridging through Foundry was an unnecessary indirection — the SPIFFE ID should map directly to Entra identities.

3. **Simpler deployment.** Removing Foundry eliminates an entire infrastructure module (Cognitive Services account + model deployment), a Python script with retry logic, and multiple gotchas (soft-deleted accounts, API version sensitivity, role propagation delays on `agents/write` vs `agents/read`).

4. **Cleaner demo story.** "Entra Agent ID → SPIFFE → mTLS + RBAC" is a direct, compelling chain. "Entra Agent ID → Foundry Agent ID → SPIFFE → mTLS + RBAC" was confusing for stakeholders.

## Consequences

- **Positive:** Simpler infra, faster deploys, clearer identity chain, fewer failure modes
- **Positive:** RBAC policy is now name-based rather than Foundry-ID-based, making it human-readable
- **Negative:** Portal UI needed updates (some Foundry references in display logic remain as bugs to fix)
- **Negative:** Any scripts or docs referencing the old SPIFFE format need updating

## Follow-Up Fixes Required After Removal

The removal was a large change (22 files) and surfaced several follow-up bugs:

1. **`create-entra-agent-ids.py` still had Foundry references** — leftover imports and variable names (commit `3d4abf0`)
2. **`deploy.sh` used undefined `SPIRE_SERVER_IP`** — should be `SPIRE_SERVER_FQDN` (commit `e54836c`)
3. **`deploy.sh` read wrong azd env variable names** — `ENTRA_BP_OID` vs `ENTRA_BLUEPRINT_OBJECT_ID` (commit `ad7a47c`)
4. **`az vm run-command invoke` calls had no timeout** — could hang indefinitely on macOS (commit `3f8592c`)

## Alternatives Considered

- **Keep Foundry but make it optional:** Rejected. Optional complexity is still complexity. If it's not enforcing anything, it shouldn't be in the critical path.
- **Use Foundry Agent IDs as the canonical identity:** Rejected. Entra Agent Identity is the Microsoft-endorsed identity primitive for agents. Foundry IDs are implementation details of the AI platform, not identity anchors.

## Related

- ADR-007: Container Apps, not AKS (mentions Foundry hosting)
- `docs/runbooks/hard-won-learnings.md` — Learnings #10-14 are Foundry-specific (now historical)
