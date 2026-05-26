# Parallel Deployments

The repo now supports multiple fully functional Azure deployments running at the same time without resetting each other's Entra federated identity credentials.

## Why This Was Needed

Azure resources were already environment-scoped, but several Microsoft Entra objects used fixed tenant-wide names:

- Agent Identity Blueprint
- Agent Identity display names
- federated identity credential names
- portal app registrations

That caused new deployments to repair or recreate the same tenant objects and break token exchange in an older environment.

## Current Scope Model

Two environment modes exist:

| Mode | Meaning |
|---|---|
| `legacy` | preserve historical names for an existing environment |
| `scoped` | derive new tenant object names from `AZURE_ENV_NAME` |

The deploy scripts persist:

- `AIM_ENV_SCOPE_MODE`
- `AIM_ENV_SCOPE_KEY`

New environments default to `scoped`. Existing environments with stored legacy bootstrap state stay `legacy`.

## What Gets Scoped

Scoped for new environments:

- Agent Identity Blueprint display name
- Agent Identity display names
- federated identity credential names
- portal management app registration
- security portal app registration

Shared tenant-wide:

- `Identity Research for Agent Management Using SPIFFE Administrators`
- `Identity Research for Agent Management Using SPIFFE Viewers`
- provisioner app
- custom security attribute schema
- generic high-risk Conditional Access model

## Naming Rules

Examples for environment `aim-example`:

| Object | Example |
|---|---|
| Blueprint | `Identity Research for Agent Management Using SPIFFE Budget Backend Agents [aim-example]` |
| Agent identity | `aim-aim-example-budget-report` |
| FIC | `aim-fic-aim-example-budget-report` |
| Portal management app | `Identity Research for Agent Management Using SPIFFE Portal - Management [aim-example]` |
| Security Portal app | `Identity Research for Agent Management Using SPIFFE Portal - Security Portal Mock [aim-example]` |

## Safe Deploy Workflow

```bash
azd env new aim-example
azd env select aim-example
./deploy.sh --new
```

Before touching Entra objects, the deploy script prints an Entra scope preflight showing:

- scope mode
- scope key
- blueprint name
- Agent Identity names
- FIC names
- portal app names

## Cleanup Behavior

`scripts/cleanup-entra-agent-ids.py` is current-environment-scoped by default. Tenant-wide cleanup is explicit and must be requested with `--all-envs`.

## Related Reading

- [Authentication Flows](../reference/authentication-flows.md)
- [Quickstart](../getting-started/quickstart.md)
