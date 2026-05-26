# Layer 3: OAuth2 and JWT

Layer 3 proves that the caller is presenting a valid Microsoft Entra token for the target resource. This is separate from transport identity and separate from admin governance.

## What Gets Validated

On the governed path, the sidecar or target app validates:

- JWT signature against Entra JWKS
- issuer
- audience
- expiry and not-before
- required roles or claims for the target action

The portal and CrowdStrike mock use the shared validator in `src/shared/jwt_validator.py` and fail closed when JWKS fetch or token validation fails.

## Why Layer 3 Exists

Transport identity says which workload connected. JWT validation says whether that workload also holds the expected Entra-issued application token for the requested resource.

That matters because:

- a caller can have a valid SPIFFE identity but no token for the resource
- a caller can have a token for the wrong audience
- a caller can have a token without the required app role

## Two Main Token Flows

### Browser to Portal

- Browser signs in with MSAL redirect flow
- Portal backend validates the bearer token or ID token claims
- Group membership decides `admin` vs `viewer`

### Agent to Protected Resource

- Caller acquires an Entra token for the target resource
- Target sidecar or app validates signature, audience, expiry, and role requirements
- The request proceeds only if Layers 1 and 2 also passed

## Fail-Closed Rules

Security-sensitive paths do not treat token errors as "no token required":

- JWKS unavailable means deny
- invalid token means deny
- missing required role means deny
- unexpected claim shape means deny

## OData and Graph Usage

The repo also talks to Microsoft Graph for Entra provisioning and governance. Those Graph queries often use OData filters. Current code escapes filter values before issuing those queries so identity provisioning and portal governance do not accidentally create an injection surface.

That OData usage is internal control-plane behavior, not a public API surface for callers.

## Related Reading

- [Authentication Flows](../../reference/authentication-flows.md)
- [Parallel Deployments](../../developer/parallel-deployments.md)
