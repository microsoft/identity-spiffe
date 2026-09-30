# Layer 4: Conditional Access and Admin Governance

Layer 4 is the admin override plane. It answers whether the organization currently allows the caller to operate, even when the developer-configured transport and RBAC layers would otherwise allow it.

## Two Enforcement Moments

### Layer 4a: Token-Time Governance

Microsoft Entra can block or shape token issuance before the request reaches the resource:

- deny token issuance
- require stronger conditions
- apply organization-wide policy to the caller identity

### Layer 4b: Data-Plane Governance

The platform also re-evaluates governance at request time through sidecar or app-layer checks:

- current agent risk
- current custom security attribute values
- current policy/tag match state
- current `agent_state` kill-switch behavior

This closes the gap between token issuance time and request time.

## What Is Shared Versus Scoped

Shared across environments:

- Conditional Access policy model
- custom security attribute schema such as `AgentIdentity.Department`
- tenant-wide admin and viewer groups for portal access

Scoped per environment:

- Agent Identity Blueprint for new scoped environments
- agent identities
- federated identity credentials
- env-scoped portal app registrations

That split keeps the governance model reusable while isolating the actual governed service principals per environment.

## Common Governance Controls In This Repo

- risk-based deny
- tag matching through Entra custom security attributes
- `agent_state` enabled or disabled
- sync from Microsoft Graph into the local policy and risk views

## Why Layer 4 Is Separate

Layers 1 to 3 express what the application owner intended. Layer 4 expresses what the enterprise currently allows. In regulated environments those are different authorities and both must exist.

## Data-Plane Evidence and Cache Contract

The sidecar evaluates the disabled-agent kill switch, Graph-sourced risk policy,
and target-tag governance **before RBAC and JWT**. The shared Python evaluator
applies the same risk-policy availability distinction to direct A2A calls.

- A configured CA policy cache must successfully observe a policy list before
  it can allow traffic. Initial outages, invalid JSON, and missing/null `value`
  arrays are unavailable, not an empty list. The sidecar denies at Layer 4 with
  `403 ca_policy_unavailable`; Python returns a fail-closed block.
- A successfully observed empty list, or a list with no enabled blocking risk
  policies, imposes no risk restriction. Disabled, report-only, and non-block
  policies retain their existing semantics. Tag checks and later layers still
  apply.
- Failed policy refreshes preserve the last-known-good list, including a
  legitimately empty list; they do not reset it or renew the successful-fetch
  timestamp. This retains the existing stale-policy behavior until a successful
  refresh replaces it. It is not proof of current tenant state during an outage.
  `/mgmt/ca-policy-effective` exposes `ready`, `last_fetch`, and `last_error` so
  unavailable startup and stale-but-initialized policy remain distinguishable.
- When risk blocking is active, absent stores/entries and unrecognized risk
  values deny with `403 agent_risk_unavailable`. The sidecar risk API reports
  missing evidence and initial `previous_level` as `unknown`, never `low`.
  An authenticated explicit low-risk signal is required to permit low risk;
  a process restart does not manufacture one.
- `CA_RISK_PROVIDER=sidecar` remains explicitly separate from `entra` in Python.
  Entra mode never uses sidecar fallback evidence. A Graph response must include
  a recognized `riskLevel` (`none`, `low`, `medium`, or `high`) before
  `confirmedSafe` can clear it. The existing resolved-service-principal
  `riskyAgents` 404/no-risk behavior is unchanged.
- A configured `TagStore` is authoritative. Missing, removed, or empty Graph
  tags cannot fall back to an allowing YAML `ca.agent_tag`; required tag
  mismatch denies with `403 agent_tag_mismatch`. Populating the store through
  authenticated attribute synchronization restores matching callers. The
  explicit `skip_target_tag_check` exemption affects only tags, not the disabled
  state or required risk checks.

Optional integration behavior is unchanged: an engine with no CA policy cache
does not perform Graph risk enforcement, and an engine with no `TagStore`
supports static YAML-only tags. Production ingress constructs a `TagStore`;
an unpopulated production store therefore denies required tags rather than
using YAML as evidence. These prototype modes do not claim full tenant CA
coverage or implement the generic filter expressions tracked in #31.

## Related Reading

- [Admin Governance Layer](../admin-governance-layer.md)
- [Authentication Flows](../../reference/authentication-flows.md)
- [ADR-010: Conditional Access as admin governance](../../decisions/010-conditional-access-admin-governance.md)
