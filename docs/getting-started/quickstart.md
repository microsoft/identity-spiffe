# Quickstart

This quickstart is for developers working on the current Azure Container Apps deployment model.

## Prerequisites

- Azure CLI `az`
- Azure Developer CLI `azd`
- Python 3.10+
- Docker or remote ACR build access through `az acr build`
- Access to the target Azure subscription and Microsoft Entra tenant

## Repo Setup

```bash
git clone https://github.com/microsoft/identity-spiffe.git
cd identity-spiffe
az login
azd auth login
```

Create or select an `azd` environment before deploying:

```bash
azd env new aim-myenv
azd env select aim-myenv
```

## Full Deployment

Use a full deploy when anything below changes:

- agent code under `src/`
- sidecar runtime or policy behavior
- SPIRE or attestation logic
- Entra Agent Identity or Conditional Access bootstrap
- infrastructure under `infra/`

```bash
./deploy.sh --new
```

Use `--reuse=<resource-group>` only when you intentionally want to deploy into an existing resource group.

## Portal-Only Deployment

Use the fast path when only the portal or security portal mock changed:

- `portal/`
- `securityportal-mock/`
- portal auth or config wiring in `deploy.sh`

```bash
./deploy.sh --portal-only
```

`--portal-only` rebuilds and updates the portal Container Apps without regenerating join tokens or forcing agent re-attestation.

## Local Portal Launch

After a full deploy generates `portal/portal-config.json`, you can run the portal locally:

```bash
python3 portal/server.py --port 8550 --config portal/portal-config.json
```

Open `http://localhost:8550`.

## Validate the Deployment

Run the end-to-end enforcement test matrix:

```bash
python3 scripts/test_agents.py
```

Typical local validation commands for code changes:

```bash
python3 -m py_compile portal/app/*.py
python3 -m unittest discover -s portal/tests -p 'test_*.py'
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
bash -n deploy.sh
```

## Where To Read Next

- [System Overview](../architecture/system-overview.md)
- [Management APIs](../reference/management-apis.md)
- [Authentication Flows](../reference/authentication-flows.md)
- [Parallel Deployments](../developer/parallel-deployments.md)
