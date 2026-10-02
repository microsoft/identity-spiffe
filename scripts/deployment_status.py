"""Pure deployment-health evaluation used by current-deployment.sh."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence


@dataclass(frozen=True)
class DeploymentFinding:
    code: str
    message: str


def blueprint_agents(
    service_principals: Iterable[Mapping[str, object]],
    blueprint_app_id: str,
) -> list[Mapping[str, object]]:
    return [
        principal
        for principal in service_principals
        if principal.get("agentIdentityBlueprintId") == blueprint_app_id
    ]


def missing_managed_identity_fics(
    fics: Iterable[Mapping[str, object]],
    managed_identity_principal_ids: Iterable[str],
) -> list[str]:
    known_principal_ids = set(managed_identity_principal_ids)
    missing: list[str] = []

    for fic in fics:
        issuer = str(fic.get("issuer", ""))
        subject = str(fic.get("subject", ""))
        if (
            issuer.startswith("https://login.microsoftonline.com/")
            and subject
            and subject not in known_principal_ids
        ):
            missing.append(str(fic.get("name", subject)))

    return missing


def evaluate_environment(
    *,
    resource_group_exists: bool,
    endpoint_statuses: Mapping[str, str],
    graph_query_succeeded: bool,
    missing_fic_names: Sequence[str],
) -> list[DeploymentFinding]:
    findings: list[DeploymentFinding] = []

    if not resource_group_exists:
        findings.append(
            DeploymentFinding(
                "resource_group_missing",
                "Stored Azure resource group does not exist.",
            )
        )

    for name, status in endpoint_statuses.items():
        if status != "200":
            findings.append(
                DeploymentFinding(
                    "endpoint_unreachable",
                    f"Stored {name} endpoint is unhealthy ({status}).",
                )
            )

    if not graph_query_succeeded:
        findings.append(
            DeploymentFinding(
                "graph_query_failed",
                "Microsoft Graph agent discovery failed.",
            )
        )

    if missing_fic_names:
        findings.append(
            DeploymentFinding(
                "fic_subject_missing",
                "FICs reference missing managed identities: "
                + ", ".join(sorted(missing_fic_names)),
            )
        )

    return findings
