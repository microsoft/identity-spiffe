#!/usr/bin/env python3
"""Quick check: query Entra ID Protection riskyAgents and optionally confirm safe."""
import subprocess
import sys

import httpx


def load_azd_env():
    result = subprocess.run(
        ["azd", "env", "get-values"],
        capture_output=True, text=True, timeout=10,
    )
    env = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            env[k] = v.strip('"').strip("'")
    return env


def get_graph_token(env):
    resp = httpx.post(
        "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % env["AZURE_TENANT_ID"],
        data={
            "client_id": env["ENTRA_AGENTID_CLIENT_ID"],
            "client_secret": env["ENTRA_AGENTID_CLIENT_SECRET"],
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def main():
    env = load_azd_env()
    token = get_graph_token(env)
    headers = {"Authorization": "Bearer %s" % token, "ConsistencyLevel": "eventual"}

    # Query riskyAgents
    resp = httpx.get(
        "https://graph.microsoft.com/beta/identityProtection/riskyAgents",
        headers=headers, timeout=10,
    )
    print("riskyAgents status:", resp.status_code)
    if resp.status_code != 200:
        print("Error:", resp.text[:500])
        return

    data = resp.json()
    risky = data.get("value", [])
    if not risky:
        print("  (no risky agents)")
        return

    for entry in risky:
        print("  id=%s  displayName=%s  riskState=%s  riskLevel=%s" % (
            entry.get("id", "?"),
            entry.get("displayName", "?"),
            entry.get("riskState", "?"),
            entry.get("riskLevel", "?"),
        ))

    # If --fix flag, confirm safe for all risky agents
    if "--fix" in sys.argv:
        agent_ids = [e["id"] for e in risky]
        print("\nCalling confirmSafe for %d agents: %s" % (len(agent_ids), agent_ids))
        resp2 = httpx.post(
            "https://graph.microsoft.com/beta/identityProtection/riskyAgents/confirmSafe",
            json={"agentIds": agent_ids},
            headers={**headers, "Content-Type": "application/json"},
            timeout=10,
        )
        print("confirmSafe status:", resp2.status_code)
        if resp2.status_code == 204:
            print("Success! Agents confirmed safe.")
        else:
            print("Error:", resp2.text[:500])


if __name__ == "__main__":
    main()
