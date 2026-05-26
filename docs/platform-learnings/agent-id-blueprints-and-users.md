# Agent Identities, Blueprints, and Users — Post-GA (May 1, 2026)

> **Last updated:** 2026-05-05
> **Status:** Authoritative reference. READ BEFORE designing any auth flow that touches Agent Identity, Agent Blueprint, or Agent User objects.
> Keep this document aligned with any downstream samples that implement Agent Identity flows.

---

## TL;DR — the constraints I keep forgetting

These are the load-bearing facts. If you only read one section, read this. Each item is a "this blocks you" gotcha that has cost real engineering hours.

1. **Agent Identity Blueprints CANNOT be OAuth public clients.** Microsoft enforces this at the platform level. Quoting Microsoft Learn verbatim: *"Public client capabilities aren't available, requiring all agents to operate as confidential clients. Redirect URLs aren't supported."* ([learn.microsoft.com/entra/agent-id/agent-oauth-protocols](https://learn.microsoft.com/en-us/entra/agent-id/agent-oauth-protocols), updated 2026-05-01). The Blueprint application object inherits from `application` but the `publicClient`, `spa`, and `isFallbackPublicClient` surfaces are excluded — they return `null` or are rejected on PATCH. **A Blueprint cannot be the `client_id` of a browser-based PKCE auth-code flow.**
2. **There is exactly one OAuth/redirect-URI exception for Blueprints, and it is narrow.** A Blueprint configured as an **interactive agent** (acts on behalf of users via OBO) gets a `web.redirectUris` entry — but that redirect URI is where Entra sends the user **after consent recording**, not where any auth-code lands for the Blueprint itself. The actual OAuth client in interactive flows is a **separate client app registration** (frontend / mobile / SPA / desktop), and the auth-code request uses **the agent identity's** `client_id` — not the Blueprint's. ([learn.microsoft.com/entra/agent-id/identity-platform/interactive-agent-authentication-authorization-flow](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/interactive-agent-authentication-authorization-flow), updated 2026-05-01).
3. **Agent Identities are confidential service principals, full stop.** `servicePrincipalType=ServiceIdentity`. They cannot have credentials of their own; the Blueprint impersonates them via FIC. They cannot be public clients. ([learn.microsoft.com/graph/api/resources/agentidentity?view=graph-rest-beta](https://learn.microsoft.com/en-us/graph/api/resources/agentidentity?view=graph-rest-beta), updated 2026-05-01).
4. **Microsoft Entra does NOT implement RFC 7591 Dynamic Client Registration.** There is no `registration_endpoint` in Entra v2.0's OIDC discovery doc. App registrations must be created manually via the admin center or Microsoft Graph (`POST /v1.0/applications`). Confirmed by Microsoft Q&A and observed behavior; the MCP authorization spec lists DCR as MAY-support and explicitly notes it's a backwards-compat option ([modelcontextprotocol.io/specification/2025-11-25/basic/authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)).
5. **Entra v2.0's OIDC discovery doc does NOT include `code_challenge_methods_supported`.** The MCP authorization spec **MUST**-requires this field; clients that strictly validate the AS metadata (Claude Code's MCP TS SDK, VS Code) refuse to proceed without it. Workaround: a metadata shim. ([learn.microsoft.com/entra/identity-platform/v2-protocols-oidc](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) sample response shows the omission; MCP spec section "Authorization Code Protection" says clients **MUST** refuse if the field is absent.)
6. **Entra v2.0 silently ignores RFC 8707 `resource` parameter on `/authorize`.** Entra is scope-centric: the supported pattern is `scope={resource}/.default`. Sending `resource=https://...` returns AADSTS901002 on the v1 endpoint and is silently dropped on v2. Audience binding happens through the scope's identifier URI. The MCP spec **MUST**-requires `resource` in both auth and token requests; clients send it, Entra ignores it, and tokens come back with `aud` derived from scope.
7. **Agent OBO flows do NOT use `/authorize` directly for the Blueprint.** Quoting docs verbatim: *"OBO flows using the `/authorize` endpoint aren't supported for any agent entity, ensuring all authentication occurs programmatically."* The user-facing `/authorize` step is run by the **client app** (a separate, regular public-client or web app reg), which gets a token whose `aud` is the Blueprint, then sends it to the agent backend, which then does OBO. ([learn.microsoft.com/entra/agent-id/agent-oauth-protocols](https://learn.microsoft.com/en-us/entra/agent-id/agent-oauth-protocols)).
8. **`AgentIdentity.Create`, `AgentIdentityBlueprint.Create`, `Application.ReadWrite.All`, `Application.ReadWrite.OwnedBy`, `Directory.ReadWrite.All`, and many more are BLOCKED for agents.** Granting any of these to an Agent Identity returns HTTP 400 from Graph. Any auth-flow design that tries to let an agent manage other apps will fail. ([learn.microsoft.com/graph/api/resources/agentid-platform-overview?view=graph-rest-beta](https://learn.microsoft.com/en-us/graph/api/resources/agentid-platform-overview?view=graph-rest-beta), updated 2026-04-28 — full blocked-permissions table.)
9. **GA (May 1, 2026) made `AgentIdentityBlueprint` v1.0.** The resource is now created via `POST /v1.0/applications/microsoft.graph.agentIdentityBlueprint` (NOT the older preview `/beta/agentIdentityBlueprints` collection). The 2025-07-14 doc still references the beta collection — that path is preview-era and now deprecated.
10. **Sponsor groups changed at GA.** Role-assignable groups and fixed-membership security groups are no longer accepted as group-type sponsors. Only **dynamic-membership groups** and **Microsoft 365 groups** count. Individual users still work. ([devblogs.microsoft.com/microsoft365dev/sponsor-group-type-requirements-for-agent-identities/](https://devblogs.microsoft.com/microsoft365dev/sponsor-group-type-requirements-for-agent-identities/), published 2026-05-01.)

If your design assumes any of (1)–(7), it is wrong, and you will discover this at deploy time. Don't.

---

## Object model (post-GA)

The Agent ID platform has **four** distinct first-class object types, each with a distinct Graph resource and a distinct `@odata.type`:

| Object | Graph resource | `@odata.type` | Underlying type | Distinguishing field |
|---|---|---|---|---|
| **Agent Identity Blueprint** | [`agentIdentityBlueprint`](https://learn.microsoft.com/en-us/graph/api/resources/agentidentityblueprint?view=graph-rest-1.0) | `#microsoft.graph.agentIdentityBlueprint` | application (subtype) | Created by `POST /v1.0/applications` with `@odata.type` field; subset of application properties applies |
| **Agent Identity Blueprint Principal** | [`agentIdentityBlueprintPrincipal`](https://learn.microsoft.com/en-us/graph/api/resources/agentidentityblueprintprincipal?view=graph-rest-beta) | `#microsoft.graph.agentIdentityBlueprintPrincipal` | servicePrincipal (subtype) | `servicePrincipalType = Application` |
| **Agent Identity** | [`agentIdentity`](https://learn.microsoft.com/en-us/graph/api/resources/agentidentity?view=graph-rest-beta) | `#microsoft.graph.agentIdentity` | servicePrincipal (subtype) | `servicePrincipalType = ServiceIdentity` |
| **Agent User** | `agentUser` | `#microsoft.graph.agentUser` | user (subtype) | Token has `idtyp=user`; `identityParentId` links to the Agent Identity |

Lifecycle hierarchy:

```
Agent Identity Blueprint (application object)
  └─ Agent Identity Blueprint Principal (service principal — runtime presence in a tenant)
      └─ Agent Identity (service principal, ServiceIdentity subtype)
          └─ Agent User (user object, optional, 1:1 with the Agent Identity)
```

Quoting [learn.microsoft.com/en-us/entra/agent-id/key-concepts](https://learn.microsoft.com/en-us/entra/agent-id/key-concepts) (updated 2026-05-01):

> *"An agent identity is the primary identity an AI agent uses to authenticate to systems and access resources. Unlike user accounts, agent identities don't have credentials of their own. They authenticate using tokens issued by their agent identity blueprint."*

> *"An agent identity blueprint is an object in Microsoft Entra ID that serves as the template and authentication foundation for one or more agent identities. The blueprint holds credentials and uses them to acquire tokens on behalf of all agent identities created from it."*

### Agent Identity Blueprint

Created via:

```http
POST https://graph.microsoft.com/v1.0/applications/
OData-Version: 4.0
Authorization: Bearer <token-with-AgentIdentityBlueprint.Create>
Content-Type: application/json

{
  "@odata.type": "Microsoft.Graph.AgentIdentityBlueprint",
  "displayName": "...",
  "sponsors@odata.bind": ["https://graph.microsoft.com/v1.0/users/<id>"],
  "owners@odata.bind": ["https://graph.microsoft.com/v1.0/users/<id>"]
}
```

Source: [learn.microsoft.com/en-us/entra/agent-id/create-blueprint](https://learn.microsoft.com/en-us/entra/agent-id/create-blueprint) (updated 2026-05-01).

The Blueprint **inherits from `application`** but Microsoft has explicitly excluded several application properties:

> *"While this resource inherits from **application**, some properties are not applicable and return `null` or default values. These properties are excluded from the table below."* ([Graph v1.0 reference](https://learn.microsoft.com/en-us/graph/api/resources/agentidentityblueprint?view=graph-rest-1.0))

The supported property list, per the v1.0 reference:

- `api` (apiApplication) — ✅ supports `oauth2PermissionScopes` for the `access_agent` scope used by interactive agents
- `appId`, `appRoles`, `displayName`, `description`, `identifierUris`, `signInAudience`, `tags`, `info`, `requiredResourceAccess`, `optionalClaims`, `keyCredentials`, `passwordCredentials`, `verifiedPublisher`, `groupMembershipClaims`, `tokenEncryptionKeyId`, `serviceManagementReference` — ✅ all standard application fields
- `web` (webApplication) — ✅ supports `redirectUris`, `implicitGrantSettings`, `homePageUrl`, `logoutUrl` — used **only** for the consent-recording redirect for interactive agents (see Section 3.1)
- `managerApplications` — ✅ new for Agent ID; up to 10 first-party Microsoft apps that can manage the Blueprint without `AgentIdentityBlueprintPrincipal.ReadWrite.All`
- `inheritablePermissions` (relationship) — ✅ new; defines scopes that auto-inherit to child Agent Identities

**Critically absent from the supported-properties list (verified by inspecting the JSON representation):**

- `publicClient` — ❌ no `redirectUris` for native/desktop/CLI apps
- `spa` — ❌ no SPA redirect URIs
- `isFallbackPublicClient` — ❌ cannot be flipped to fallback-public-client mode

This is enforced at the API surface: `az ad app update` returns *"incompatible with Agent Blueprints"* and Graph PATCH rejects setting these fields on Agent Blueprint applications.

`signInAudience` for Blueprints supports the standard four values (`AzureADMyOrg` (default), `AzureADMultipleOrgs`, `AzureADandPersonalMicrosoftAccount`, `PersonalMicrosoftAccount`), but **Agent Identities themselves are always single-tenant regardless** — quoting [agent-autonomous-app-oauth-flow](https://learn.microsoft.com/en-us/entra/agent-id/agent-autonomous-app-oauth-flow):

> *"Agent identities are always single-tenant regardless of their parent Agent identity blueprint's tenancy model. Each agent identity operates within one tenant's security and policy boundaries."*

### Agent Identity Blueprint Principal

Auto-created when a Blueprint is added to a tenant, via:

```http
POST https://graph.microsoft.com/v1.0/serviceprincipals/microsoft.graph.agentIdentityBlueprintPrincipal
{ "appId": "<blueprint-appId>" }
```

This is **not** auto-created by Graph when the Blueprint is created — you must call this explicitly after the Blueprint creation step. (CLAUDE.md non-negotiable: *"Always create BlueprintPrincipal explicitly after Blueprint — it is NOT auto-created."*)

Token claims: when the Blueprint acquires tokens, the token's `oid` claim references the Blueprint Principal's object ID, not the Blueprint application's appId. Audit logs likewise attribute Blueprint actions to this principal.

### Agent Identity

Created from a Blueprint, single-tenant by definition. The full property list is small:

```json
{
  "@odata.type": "#microsoft.graph.agentIdentity",
  "id": "<oid>",
  "accountEnabled": true,
  "agentIdentityBlueprintId": "<blueprint-appId>",
  "createdByAppId": "<blueprint-appId>",
  "createdDateTime": "...",
  "displayName": "...",
  "servicePrincipalType": "ServiceIdentity",
  "tags": []
}
```

Note: `servicePrincipalType` is fixed at `"ServiceIdentity"` for all Agent Identities. There is no redirect-URI field, no credential field, no `web`/`spa`/`publicClient`. The Agent Identity is purely a service principal that holds **permissions and audit identity** — the Blueprint holds the credentials and impersonates it.

Source: [Graph beta resource](https://learn.microsoft.com/en-us/graph/api/resources/agentidentity?view=graph-rest-beta), updated 2026-05-01.

### Agent User

Optional, 1:1 with an Agent Identity. Created via:

```http
POST https://graph.microsoft.com/beta/users
{
  "@odata.type": "microsoft.graph.agentUser",
  "displayName": "...",
  "userPrincipalName": "...@tenant.onmicrosoft.com",
  "identityParentId": "<agent-identity-oid>",
  "accountEnabled": true
}
```

The Agent User's tokens carry `idtyp=user` so they appear as user identities to every M365 API. But they cannot have passwords, passkeys, or MFA factors. Quote from [learn.microsoft.com/entra/agent-id/agent-users](https://learn.microsoft.com/en-us/entra/agent-id/agent-users) (updated 2026-05-01):

> *"The agent's user account doesn't have regular credentials like passwords. Instead, it's restricted to using the credentials provided through its parent relationship... [It] can't have credentials like passwords or passkeys. The only credential type it supports is the agent identity reference to its parent. So even if the agent's user account behaves as a user, its credentials are confidential client credentials."*

> *"Once established, this relationship is immutable and serves as a cornerstone of the security model for the agent's user account. The relationship is a one-to-one (1:1) mapping. Each agent identity can have at most one associated agent's user account, and each agent's user account is linked to exactly one parent agent identity, itself linked to exactly one agent identity blueprint application."*

---

## Capabilities and constraints by object

### 2.1 Agent Identity Blueprint

**Supported flows:**
- `client_credentials` — for autonomous/app-only token acquisition (the Blueprint impersonates the Agent Identity using FIC). The Blueprint itself uses its credential (cert, secret, or FIC against a managed identity) to mint a token bound to an Agent Identity.
- `urn:ietf:params:oauth:grant-type:jwt-bearer` (OBO) — when the client app sends a user-token whose `aud` is the Blueprint, the agent backend exchanges that token for a downstream token via OBO.
- `refresh_token` — for background user-delegated operations.
- **`authorization_code` indirectly**, with caveats. The Blueprint can be the *audience* of an auth-code flow run by a separate client app (see Section 3.1), and its `web.redirectUris` can record consent. But the Blueprint **cannot itself be the `client_id`** of a browser-based PKCE flow.

**Unsupported / blocked flows:**
- `authorization_code` flow with the Blueprint as `client_id` and a public-client redirect URI. Microsoft enforces this.
- `device_code` flow — Blueprints are confidential clients only; device code is a public-client flow.
- Implicit grant.
- ROPC (username/password).
- OBO via `/authorize` (i.e., the user-interactive part of OBO is delegated to a separate client app).

**Required permissions to create:**
- `AgentIdentityBlueprint.Create` (delegated)
- `AgentIdentityBlueprint.AddRemoveCreds.All` (for adding credentials)
- `AgentIdentityBlueprint.UpdateAuthProperties.All` (for `oauth2PermissionScopes`, redirectUris)
- `AgentIdentityBlueprintPrincipal.Create` (for the principal)
- Roles: `Privileged Role Administrator` (least privilege for granting Graph application permissions), `Cloud Application Administrator` or `Application Administrator` (for delegated permissions), and `Agent ID Developer` or `Agent ID Administrator` (for the Blueprint operations).

Source: [learn.microsoft.com/entra/agent-id/create-blueprint](https://learn.microsoft.com/en-us/entra/agent-id/create-blueprint) updated 2026-05-01.

**Tenant policies that apply:**
- Conditional Access policies targeting the Blueprint or its agent identities.
- App credential lifecycle policies (max secret lifetime).
- Sponsor group-type restriction (post-GA: dynamic-membership groups + M365 groups only; role-assignable groups and fixed-membership security groups rejected).
- The full table of high-risk Microsoft Graph permissions blocked for agent identities — `Application.ReadWrite.All`, `Application.ReadWrite.OwnedBy`, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `User.ReadWrite.All`, etc. — applies to all Agent Identities created from the Blueprint via `requiredResourceAccess`. Including a blocked permission returns HTTP 400.

Source: [graph.api.resources/agentid-platform-overview](https://learn.microsoft.com/en-us/graph/api/resources/agentid-platform-overview?view=graph-rest-beta) updated 2026-04-28.

### 2.2 Agent Identity

**Supported flows:**
- `client_credentials` — autonomous app-only operations. The Blueprint mints a token whose subject is the Agent Identity using FIC.
- `urn:ietf:params:oauth:grant-type:jwt-bearer` — both client-credential extension and OBO flows.
- `refresh_token` — for background user-delegated operations.

**Unsupported / blocked flows:**
- All interactive flows (authorization_code, device_code, implicit, ROPC). Quote: *"OBO flows using the `/authorize` endpoint aren't supported for any agent entity"*.
- Public-client capabilities of any kind.
- Independent credential management — the Blueprint is the credential holder; the Agent Identity has none of its own.

**Required permissions to create:**
- `AgentIdentity.Create` (typically delegated to the Blueprint via the `AgentIdentity.CreateAsManager` permission, which is itself an agent-blocked permission for everything except the Blueprint Principal that owns it).

**Tenant policies that apply:**
- Direct Conditional Access targeting (per agent identity, by Object ID, by custom security attribute, by Blueprint).
- Identity Protection (`agentRiskDetection`, `riskyAgent` Graph resources).
- ID Governance (access reviews, entitlement management).
- The blocked-permissions table — `requiredResourceAccess` is rejected if it includes any blocked permission, with HTTP 400.

### 2.3 Agent User

**Supported flows:**
- The 3-hop **`user_fic`** flow that the Agent Identity runs to mint tokens **as** the Agent User. The third hop uses `grant_type=user_fic` (NOT `urn:ietf:params:oauth:grant-type:jwt-bearer`), `username=<agentuser>@tenant.onmicrosoft.com`, `client_assertion=<T1>`, and `user_federated_identity_credential=<T2>`. Source: [agent-user-oauth-flow](https://learn.microsoft.com/en-us/entra/agent-id/agent-user-oauth-flow) updated 2026-05-01.

**Unsupported / blocked flows:**
- All human-interactive flows (no passwords, no passkeys, no MFA, no device code, no authorization_code where the user is the subject). Cannot sign in directly.
- Cannot be assigned privileged admin roles.
- Cannot be added to role-assignable groups.

**Required permissions to create:**
- `AgentIdUser.ReadWrite.IdentityParentedBy` (when the Blueprint creates its own Agent User), or
- `AgentIdUser.ReadWrite.All` (when a separate client creates Agent Users across Blueprints).

**Required licensing for resource access:**
- M365 license (E5, Teams Enterprise, M365 Copilot, etc.) for mailbox / Teams / OneDrive provisioning. Without a license, the Agent User exists but has no resources.
- Resource provisioning (mailbox, OneDrive) typically completes in 10–15 min, can take up to 24h.

Source: [learn.microsoft.com/entra/agent-id/agent-users](https://learn.microsoft.com/en-us/entra/agent-id/agent-users) updated 2026-05-01.

**Tenant policies that apply:**
- Directory quotas (default 50K objects without verified domain, 300K with one). Each Agent User counts.
- Soft-delete: Agent Users persist 30 days at full quota weight, ~30 more days at partial weight, then hard-delete frees the quota. Total ~60 days. Pooling of Agent Users for ephemeral sessions is a known anti-pattern (CLAUDE.md's `entra-agent-users.md` documents this in detail).
- Conditional Access policies CAN target Agent Users specifically (post-GA capability, was preview at time of 2025-07-14 docs).

---

## Recommended patterns

### 3.1 The "MCP server with cert-based machine flows AND browser-based PKCE for humans" pattern

This is the question that triggered the doc. The answer: **two separate Entra app registrations, full stop.**

#### The two-app-reg pattern (Microsoft-recommended)

```
┌──────────────────────────────────────────────────────────────────┐
│  App registration #1: <YourService> Blueprint                    │
│  - @odata.type: agentIdentityBlueprint                           │
│  - signInAudience: AzureADMyOrg                                  │
│  - api.oauth2PermissionScopes: [{ value: "access_agent",         │
│      type: "User", isEnabled: true }]                            │
│  - identifierUris: ["api://<blueprint-appId>"]                   │
│  - keyCredentials: [<cert>] OR FIC against managed identity      │
│  - web.redirectUris: ["https://yourservice.example/authorize"]   │
│      (only needed if doing interactive OBO)                      │
│  - publicClient.redirectUris: <NOT SUPPORTED>                    │
│  - spa.redirectUris: <NOT SUPPORTED>                             │
│                                                                  │
│  Used for:                                                       │
│    - Autonomous client_credentials flows (cert/FIC → Agent       │
│      Identity → resource token)                                  │
│    - The "audience" / resource-server side of OBO flows          │
│      (validates incoming user tokens whose aud matches this      │
│      Blueprint's appId)                                          │
└──────────────────────────────────────────────────────────────────┘
                              ▲
                              │ "I want to call this resource server"
                              │ scope = api://<blueprint-appId>/access_agent
                              │
┌──────────────────────────────────────────────────────────────────┐
│  App registration #2: <YourService> MCP Client                   │
│  - Standard application object (NOT agentIdentityBlueprint)      │
│  - signInAudience: AzureADMyOrg (or multitenant if needed)       │
│  - publicClient.redirectUris OR spa.redirectUris:                │
│      ["http://localhost", "http://127.0.0.1"]                    │
│  - isFallbackPublicClient: true (if no platform configured)      │
│  - requiredResourceAccess: [api://<blueprint-appId>/access_agent]│
│  - NO credentials (it's a public client)                         │
│                                                                  │
│  Used for:                                                       │
│    - Browser-based OAuth 2.1 PKCE auth-code flow                 │
│    - The MCP-spec-required `client_id` in the /authorize call    │
│    - Holds the human's refresh token (90-day rolling default)    │
│                                                                  │
│  This app reg is what desktop or IDE MCP clients use as their    │
│  OAuth client_id when doing dynamic registration fallback. The   │
│  DCR shim returns this app's appId to the MCP client.            │
└──────────────────────────────────────────────────────────────────┘
```

The MCP Client app reg is a **separate, ordinary application object** — created via `POST /v1.0/applications` WITHOUT `@odata.type=agentIdentityBlueprint`. It is NOT subject to the agent platform's public-client restrictions because it is not an agent.

The MCP Client app reg is **delegated**: it requests the Blueprint's `access_agent` scope, the user consents, and the resulting access token has `aud = <blueprint-appId>`. The MCP server validates this token and accepts it.

#### Why this works

- The user goes through `/authorize` with the **MCP Client app's** `client_id` and a localhost redirect URI. This works because the MCP Client app is an ordinary public-client app, not an agent.
- Entra mints an auth code, the MCP Client exchanges it for a token at `/token` with PKCE, and the token's `aud` is the Blueprint (because the requested scope is `api://<blueprint-appId>/access_agent`).
- The MCP server (acting as the resource server / Blueprint's API layer) validates the token. It already accepts tokens with this audience.
- The MCP server, if it needs to call downstream APIs as the user, runs the standard agent OBO flow (Blueprint exchanges client credential for `T1`, Agent Identity exchanges `T1`+user-token for downstream resource token).

Microsoft's [interactive-agent-authentication-authorization-flow](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/interactive-agent-authentication-authorization-flow) doc (updated 2026-05-01) describes exactly this pattern, quoting verbatim:

> *"After authorization is configured, the client app (such as a frontend or mobile app) initiates an OAuth 2.0 authorization code request to obtain a token where the audience is the agent identity blueprint. **In this step, `client_id` refers to the client app's own registered application ID, not the agent identity or agent identity blueprint ID.**"*

That is the unambiguous Microsoft-recommended pattern. Prior designs that treated the Blueprint itself as the public OAuth client missed this distinction.

#### Alternative considered: the MCP server implements OAuth 2.1 endpoints itself

In this alternative, the MCP server becomes its own OAuth 2.1 authorization server, implementing `/authorize`, `/token`, and PKCE state, then brokering to Entra on the backend through the existing FIC exchange. This works but is significantly more code; only consider it if (a) you cannot create a second app registration, or (b) you need the MCP server to be portable across IdPs.

### 3.2 DCR (RFC 7591) support in Entra

**Microsoft Entra ID does not implement RFC 7591.** There is no `registration_endpoint` in `/.well-known/openid-configuration` for any tenant, audience, or workload-vs-external tenant config. (Confirmed by Microsoft Q&A and observed: search for "Does EntraID has a plan to introduce Dynamic Client Registration Feature" — no plan announced.)

**Workaround patterns:**

1. **MCP control plane / DCR shim.** The MCP server (or a sidecar) exposes a `/register` endpoint that accepts RFC 7591 registration requests, validates them, and returns a static, pre-registered Entra app registration's `appId` as the `client_id`. The MCP server also exposes `/.well-known/oauth-authorization-server` with the AS metadata pointing at Entra's `/authorize` and `/token` endpoints. Claude Code's MCP client follows the discovery, "registers" with the shim, gets back the static `client_id`, and uses it for the auth-code flow. This is the recommended shim approach when an MCP client expects dynamic registration but the backing IdP does not support it.
2. **OAuth Client ID Metadata Documents** (draft-ietf-oauth-client-id-metadata-document-00). The MCP spec lists this as the **preferred** registration mechanism (above DCR in priority order). The client hosts its metadata at an HTTPS URL and uses the URL as `client_id`. Entra does not currently support this either.
3. **Pre-registration** — manually create the public-client app registration once per server, distribute the `client_id` to MCP clients via configuration. Highest friction, but works against Entra today.

Quote from MCP spec: *"MCP clients and authorization servers **MAY** support the OAuth 2.0 Dynamic Client Registration Protocol [RFC7591] to allow MCP clients to obtain OAuth client IDs without user interaction. This option is included for backwards compatibility with earlier versions of the MCP authorization spec."*

So DCR is NOT mandatory for MCP — only MAY. Designing your auth flow to require it against Entra means you've designed yourself into a corner.

### 3.3 RFC 8707 resource indicators in Entra

Entra v2.0's **token endpoint accepts `resource` but ignores it** (unsupported parameter, silently dropped). Entra is scope-centric: audience binding is implicit in the requested scope.

- For a token whose `aud` should be `<blueprint-appId>`, request `scope=api://<blueprint-appId>/.default` or `scope=api://<blueprint-appId>/access_agent`.
- Sending `resource=api://<blueprint-appId>` alongside is harmless on v2.0 — it's ignored.
- Sending `resource=` to v1 endpoints can return `AADSTS901002` ("the resource request parameter is not supported") in some configurations.
- The MCP spec **MUST**-requires the `resource` parameter; clients send it, and per the spec: *"MCP clients MUST send this parameter regardless of whether authorization servers support it."* So sending it does no harm.

Audience validation on the MCP server side still works: validate that `aud` matches your Blueprint's `appId` (or its identifier URI). Since the audience comes from the scope, the MCP spec's security goal — token audience binding — is achieved through Entra's scope mechanism, just not through the IETF-standard parameter.

### 3.4 OIDC discovery shim for `code_challenge_methods_supported`

Entra v2.0's `/.well-known/openid-configuration` does NOT include `code_challenge_methods_supported`. Verbatim from the [v2-protocols-oidc sample](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) (the JSON sample listed only `authorization_endpoint`, `token_endpoint`, `token_endpoint_auth_methods_supported`, `jwks_uri`, `userinfo_endpoint`, `subject_types_supported`).

PKCE works against Entra. The metadata is just missing. MCP clients (Claude Code's MCP TypeScript SDK and VS Code in particular) strictly Zod-validate the AS metadata response and refuse to proceed if `code_challenge_methods_supported` is absent. The MCP spec mandates this:

> *"OAuth 2.0 Authorization Server Metadata: If `code_challenge_methods_supported` is absent, the authorization server does not support PKCE and MCP clients **MUST** refuse to proceed."*

> *"OpenID Connect Discovery 1.0: ... MCP clients **MUST** verify the presence of `code_challenge_methods_supported` in the provider metadata response. If the field is absent, MCP clients **MUST** refuse to proceed."*

**Workaround:** the MCP server hosts an OIDC discovery shim at `/.well-known/oauth-authorization-server-entra` that fetches Entra's discovery doc, injects `code_challenge_methods_supported: ["S256"]` and `grant_types_supported`, and returns the result. The shim does NOT change the issuer or the endpoint URLs (so token signatures still validate against Entra's JWKS). This was the PR #47 plan's correct part.

---

## What changed at the May 1, 2026 GA

Earlier preview-era notes described Agent ID as beta-only and Graph-beta-only. Those statements are now outdated after the May 1, 2026 GA changes.

### What's GA'd

- **Microsoft Agent 365** (which includes Entra Agent ID) became GA on **May 1, 2026**, $15/user/month standalone or as part of M365 E7 ($99/user/month). Source: [Microsoft Security blog 2026-05-01](https://www.microsoft.com/en-us/security/blog/2026/05/01/microsoft-agent-365-now-generally-available-expands-capabilities-and-integrations/).
- The `agentIdentityBlueprint` resource is in **Microsoft Graph v1.0** (was beta-only). Created via `POST /v1.0/applications/microsoft.graph.agentIdentityBlueprint`. The `agentIdentity` and `agentUser` resources remain in **beta** (the v1.0 ref says "Other Supported Versions: graph-rest-1.0" but the canonical doc URL still uses `view=graph-rest-beta`).
- **Conditional Access for Agent Identities** is generally available (was preview as of March 2026) — agent risk, agent custom security attributes, agent identity targeting are all live.
- **ID Protection for agents** (`agentRiskDetection`, `riskyAgent` resources) is GA.
- **ID Governance for agents** (access reviews, entitlement management for agent identities) is GA.
- **Lifecycle Workflows for agent sponsors** (Preview).

### What's renamed / restructured

- The **Agent Registry** and **Agent Collections** blades in the Entra admin center are **retired as of May 1, 2026**. The Graph beta `agentRegistry` / `agentCardManifest` / `agentInstance` / `agentCollection` resources will be **deprecated** and replaced by Agent 365-powered registry APIs. Agents registered via the old API will need to be re-registered.
- The doc set moved: the old `/agent-id/identity-platform/...` URLs (used in the 2025-07-14 docs) are being consolidated under `/agent-id/...` directly. Many old URLs still resolve but redirect.

### Sponsor group-type tightening (this is a breaking change)

Quote from [devblogs.microsoft.com/microsoft365dev/sponsor-group-type-requirements-for-agent-identities/](https://devblogs.microsoft.com/microsoft365dev/sponsor-group-type-requirements-for-agent-identities/) (published 2026-05-01):

> *"As part of the GA release for Entra Agent ID, agent blueprints, agent blueprint principals, and agent identities only accept dynamic membership groups and Microsoft 365 groups as group-type sponsors, and role-assignable groups were supported during the public preview but aren't included in the GA release."*

> *"If your current workflows assign fixed-membership security groups or role-assignable groups as sponsors, transition to dynamic membership groups or Microsoft 365 groups before your next provisioning cycle. However, existing sponsors from other group types that are already set on your agent identities or blueprints continue to function, and individual users remain fully supported as sponsors, with no changes."*

Existing assignments grandfather; new assignments must comply.

### What's unchanged but newly load-bearing

- **Agent Blueprints have always been confidential clients.** The platform docs say it explicitly post-GA, but the same restriction was in place during preview; it just was not called out as prominently in older writeups. The sentence *"Public client capabilities aren't available, requiring all agents to operate as confidential clients. Redirect URLs aren't supported."* now appears verbatim in [agent-oauth-protocols](https://learn.microsoft.com/en-us/entra/agent-id/agent-oauth-protocols) (updated 2026-05-01).
- **Agent Identities are always single-tenant.** This was true in preview too; the GA docs clarify it.

### Canonical post-GA doc URLs

| Topic | Old (preview) URL | New (GA) URL |
|---|---|---|
| What is Agent ID | (none — was just blog posts) | https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id |
| Key concepts | /entra/agent-id/identity-platform/key-concepts | https://learn.microsoft.com/en-us/entra/agent-id/key-concepts |
| Auth protocols | (deep in API ref) | https://learn.microsoft.com/en-us/entra/agent-id/agent-oauth-protocols |
| OBO flow for agents | (none) | https://learn.microsoft.com/en-us/entra/agent-id/agent-on-behalf-of-oauth-flow |
| Autonomous app flow | (none) | https://learn.microsoft.com/en-us/entra/agent-id/agent-autonomous-app-oauth-flow |
| Agent user flow | /entra/agent-id/identity-platform/autonomous-agent-request-agent-user-tokens | https://learn.microsoft.com/en-us/entra/agent-id/agent-user-oauth-flow |
| Interactive agent flow | (none — new at GA) | https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/interactive-agent-authentication-authorization-flow |
| Service principals | /entra/agent-id/identity-platform/agent-service-principals | https://learn.microsoft.com/en-us/entra/agent-id/agent-service-principals |
| Agent users | /entra/agent-id/identity-platform/agent-users | https://learn.microsoft.com/en-us/entra/agent-id/agent-users |
| Create blueprint | /entra/agent-id/identity-platform/create-blueprint | https://learn.microsoft.com/en-us/entra/agent-id/create-blueprint |
| Grant access (consent) | (scattered) | https://learn.microsoft.com/en-us/entra/agent-id/grant-agent-access-microsoft-365 |
| Blocked permissions | (none) | https://learn.microsoft.com/en-us/graph/api/resources/agentid-platform-overview?view=graph-rest-beta |

---

## Case study: Blueprint-as-public-client failure mode

### What the plan assumed

An implementation plan tried to make Entra the OAuth 2.1 authorization server visible to a desktop MCP client by reusing the Agent Identity Blueprint as the client-facing OAuth application.

The key load-bearing assumption was in Task 0 Step 2:

> *"`publicClient.redirectUris` OR `spa.redirectUris` contains at least one loopback URI (`http://localhost`, `http://localhost:<port>`, `http://127.0.0.1`)."*
> *"If public-client redirect URIs are missing → same: record the command, do not execute."*

The implicit assumption was that the Blueprint app registration **could be configured** with a `publicClient.redirectUris` entry, making it a valid OAuth client for a PKCE auth-code flow.

### What post-GA reality says

The Blueprint is created with `@odata.type=agentIdentityBlueprint`, which makes it an Agent Identity Blueprint, not an ordinary application. Per [agent-oauth-protocols](https://learn.microsoft.com/en-us/entra/agent-id/agent-oauth-protocols):

> *"Public client capabilities aren't available, requiring all agents to operate as confidential clients. Redirect URLs aren't supported."*

This applies to Agent Blueprints because they are agent entities. The platform enforcement:

- `az ad app update --id <blueprint> --public-client-redirect-uris http://localhost` returns *"incompatible with Agent Blueprints"*.
- `PATCH /applications/<blueprint> { "isFallbackPublicClient": true }` is rejected.
- `PATCH /applications/<blueprint> { "publicClient": { "redirectUris": [...] } }` is silently dropped or returns 400.

### Why the plan still seemed to make sense up to Task 0

The Task 0 verification spike correctly identified that Entra v2.0's OIDC discovery doc is missing `code_challenge_methods_supported`. That's a real finding, and the discovery-shim approach is the right fix for that part.

What the design missed was the platform-specific check: **before assuming the Blueprint can be the OAuth client, check whether Microsoft allows that at all.** RFC 8414 says nothing about Agent Identities; it is IdP-agnostic. Microsoft's enforcement happens above the protocol layer, in Graph and the `az` CLI.

### The right pattern (Phase 2A — the plan after the lesson)

Create a **second, separate** Entra app registration:

```bash
az ad app create \
  --display-name "Example MCP Client" \
  --is-fallback-public-client true \
  --public-client-redirect-uris http://localhost http://127.0.0.1
```

This creates an ordinary `application` object (NOT an `agentIdentityBlueprint`). It can be a public client, can have localhost redirect URIs, can do PKCE.

Configure it as a delegated client of the Blueprint's `access_agent` (or `access`) scope:

```bash
az ad app permission add \
  --id <mcp-client-appId> \
  --api <blueprint-appId> \
  --api-permissions <access-scope-id>=Scope
```

Update the DCR shim's `/register` route to return `<mcp-client-appId>` as the `client_id`. Add `<mcp-client-appId>` to the server's allowed-client list so JWT validation accepts the resulting tokens. The tokens will have `aud = <blueprint-appId>` because the requested scope is `api://<blueprint-appId>/access_agent`, and the `azp` claim will be `<mcp-client-appId>`.

Net flow:

1. The MCP client gets 401 from the MCP server and follows `WWW-Authenticate` to protected resource metadata.
2. PRM points at the Entra OIDC shim (which adds `code_challenge_methods_supported`).
3. MCP client follows the shim, gets Entra's actual `/authorize` and `/token` endpoints.
4. MCP client does dynamic-registration fallback at the server's `/register` shim and gets back `<mcp-client-appId>`.
5. MCP client opens browser to Entra `/authorize?client_id=<mcp-client-appId>&scope=api://<blueprint-appId>/access_agent&...`.
6. User consents (one-time), Entra redirects to `localhost:<port>` with auth code.
7. MCP client exchanges code+PKCE at `/token`, gets access token + refresh token. Token's `aud=<blueprint-appId>`.
8. MCP client sends the token to the MCP server. JWT validation accepts because `aud` matches and `azp` is in the allow-list.
9. At 12h, MCP client uses refresh token silently. No browser, no session restart.

This is Microsoft's recommended pattern from [interactive-agent-authentication-authorization-flow](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/interactive-agent-authentication-authorization-flow), adapted for MCP clients.

### Lesson generalized

When designing any auth flow that touches an Agent Identity, Agent Blueprint, or Agent User: **start from the agent-platform docs, not the Entra-as-generic-IdP docs**. The agent platform layers tight constraints on top of Entra, and those constraints are not visible from RFC 8414 / RFC 7591 / RFC 9728 alone. Specifically:

1. List every Microsoft Graph object that will be involved.
2. For each, look up its `@odata.type` in the post-GA docs and confirm what's inherited vs. excluded.
3. For each, look up its supported flows in `agent-oauth-protocols`.
4. Check `agentid-platform-overview` for blocked permissions before requesting any.
5. Only then design the OAuth/OIDC layer.

---

## Cross-references

### Microsoft official docs (canonical post-GA URLs, all verified 2026-05-05)

- [What is Microsoft Entra Agent ID?](https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id) (updated 2026-05-01)
- [Fundamental concepts in Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/key-concepts) (updated 2026-05-01)
- [Authentication protocols in agents](https://learn.microsoft.com/en-us/entra/agent-id/agent-oauth-protocols) (updated 2026-05-01) — **the load-bearing public-client constraint doc**
- [Agent OBO OAuth flow](https://learn.microsoft.com/en-us/entra/agent-id/agent-on-behalf-of-oauth-flow) (updated 2026-05-01)
- [Agent autonomous app OAuth flow](https://learn.microsoft.com/en-us/entra/agent-id/agent-autonomous-app-oauth-flow) (updated 2026-05-01)
- [Agent's user account impersonation protocol](https://learn.microsoft.com/en-us/entra/agent-id/agent-user-oauth-flow) (updated 2026-05-01)
- [Authenticate users and acquire tokens for interactive agents](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/interactive-agent-authentication-authorization-flow) (updated 2026-05-01) — **the two-app-reg pattern doc**
- [Agent identities, service principals, and applications](https://learn.microsoft.com/en-us/entra/agent-id/agent-service-principals) (updated 2026-05-01)
- [Agent identity blueprints](https://learn.microsoft.com/en-us/entra/agent-id/agent-blueprint) (updated 2026-05-01)
- [Agent's user account](https://learn.microsoft.com/en-us/entra/agent-id/agent-users) (updated 2026-05-01)
- [Create an agent identity blueprint](https://learn.microsoft.com/en-us/entra/agent-id/create-blueprint) (updated 2026-05-01)
- [Grant agents access to Microsoft 365 resources](https://learn.microsoft.com/en-us/entra/agent-id/grant-agent-access-microsoft-365) (updated 2026-05-01)
- [Microsoft Entra Agent ID APIs in Microsoft Graph](https://learn.microsoft.com/en-us/graph/api/resources/agentid-platform-overview?view=graph-rest-beta) (updated 2026-04-28) — **the blocked-permissions table**
- [agentIdentityBlueprint v1.0 resource](https://learn.microsoft.com/en-us/graph/api/resources/agentidentityblueprint?view=graph-rest-1.0) (updated 2026-04-25)
- [agentIdentity beta resource](https://learn.microsoft.com/en-us/graph/api/resources/agentidentity?view=graph-rest-beta) (updated 2026-05-01)
- [agentIdentityBlueprintPrincipal beta resource](https://learn.microsoft.com/en-us/graph/api/resources/agentidentityblueprintprincipal?view=graph-rest-beta)
- [OpenID Connect on Microsoft identity platform (v2-protocols-oidc)](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) (updated 2026-04-24) — confirms the OIDC discovery doc shape

### Official blog posts and release notes

- [Microsoft Agent 365 GA announcement (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2026/05/01/microsoft-agent-365-now-generally-available-expands-capabilities-and-integrations/) (2026-05-01)
- [Sponsor group type requirements for agent identities (devblogs.microsoft.com)](https://devblogs.microsoft.com/microsoft365dev/sponsor-group-type-requirements-for-agent-identities/) (2026-05-01) — the role-assignable-group breaking change
- [What's new in Microsoft Entra — March 2026](https://techcommunity.microsoft.com/blog/microsoft-entra-blog/what%E2%80%99s-new-in-microsoft-entra-%E2%80%93-march-2026/4502150) (April 2026)
- [Microsoft Entra releases and announcements](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new) (rolling)

### Standards (cited inline)

- [RFC 7591 — OAuth 2.0 Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591) (Entra: not implemented)
- [RFC 8414 — OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414) (Entra: partial — OIDC discovery is implemented, but missing `code_challenge_methods_supported`)
- [RFC 8707 — Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html) (Entra v2.0: silently ignored; scope-based audience binding instead)
- [RFC 9728 — OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728) (Entra: not implemented natively; MCP servers implement it themselves)
- [draft-ietf-oauth-v2-1-13 — OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13) (Entra: most security best practices supported)
- [MCP Authorization Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) — the spec MCP clients enforce

### Related docs

- **`docs/platform-learnings/Conditional-Access-Learnings.md`**: CA semantics for agents (agent risk, custom security attributes, target scoping). Complements this doc; read both when designing tenant-policy enforcement.

### Open questions / "what to keep an eye on"

1. **Will Entra add `code_challenge_methods_supported` to its OIDC discovery doc?** The MCP authorization spec's strictness is now widely deployed (Claude Code, VS Code, Cursor). Microsoft has incentive to add this field. If they do, the OIDC shim becomes a no-op and can be removed.
2. **Will Entra add an RFC 7591 registration_endpoint?** The Microsoft Q&A thread tracking this remains unanswered with no roadmap commitment. External ID / CIAM may add it before workforce tenants do.
3. **Will managerApplications be opened to non-Microsoft first-party apps?** Currently limited to Microsoft first-party apps only — meaningful agent-management automation by third parties is gated on this.
4. **Will the `agentIdentity` and `agentUser` resources move from beta to v1.0?** The Blueprint resource already moved; the others are next.
5. **Will the Agent Registry beta APIs deprecate cleanly?** The transition to Agent 365-powered registry APIs is announced but the cutover and migration tooling are not yet documented.
6. **Will Agent Users become first-class for Conditional Access targeting?** Currently CA targeting for Agent Users is layered through the parent Agent Identity; direct Agent User targeting is announced but the schema is still settling.
7. **Will Microsoft's OAuth Client ID Metadata Document support land?** This would be the cleanest fix for MCP — clients self-publish metadata at HTTPS URLs, no DCR needed. Entra has not committed to this yet.

---

*End of doc. Total ~6500 words. If you found yourself surprised by anything in here, the answer is probably to re-read sections 2.1 (Blueprint constraints) and 5 (PR #47 case study).*
