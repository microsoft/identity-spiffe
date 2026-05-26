"""Security scan service."""

from datetime import datetime, timezone
from typing import Any, Dict, List


class ScanService:
    """Evaluates live config against hardening rules."""

    def __init__(self, policy_service):
        # type: (Any) -> None
        self.policy_service = policy_service

    async def run_scan(self, request_id):
        # type: (str) -> Dict[str, Any]
        findings = []
        fetch_errors = []
        mtls_data = None
        rbac_data = None
        try:
            mtls_data = await self.policy_service.get_mtls_policy(request_id)
        except Exception as exc:
            fetch_errors.append("mTLS policy: {0}".format(exc))
        try:
            rbac_data = await self.policy_service.get_policy(request_id)
        except Exception as exc:
            fetch_errors.append("RBAC policy: {0}".format(exc))

        if fetch_errors:
            findings.append(
                {
                    "id": "scan-fetch-error",
                    "severity": "HIGH",
                    "category": "Connectivity",
                    "title": "Could not reach sidecar management API",
                    "description": "The scan could not fetch live data from the sidecar. Errors: {0}".format(
                        "; ".join(fetch_errors)
                    ),
                    "fix_type": "manual",
                    "fix_payload": {},
                }
            )

        if mtls_data:
            allowed_ids = mtls_data.get("allowed_ids", [])
            trusted_agents = {"budget-report", "budget-approval", "admin-control-plane"}
            trusted_sids = set(self.policy_service.get_agent_spiffe_id(key) for key in trusted_agents)
            control_plane_sid = self.policy_service.settings.control_plane.spiffe_id
            if control_plane_sid:
                trusted_sids.add(control_plane_sid)
            for sid in allowed_ids:
                if sid in trusted_sids:
                    continue
                agent_name = sid.split("/")[-1] if "/" in sid else sid
                for key, agent in self.policy_service.settings.agents.items():
                    if agent.spiffe_id == sid:
                        agent_name = agent.name
                        break
                findings.append(
                    {
                        "id": "mtls-untrusted-{0}".format(agent_name),
                        "severity": "HIGH",
                        "category": "mTLS",
                        "title": "Untrusted agent has network access: {0}".format(agent_name),
                        "description": (
                            "{0} is in the mTLS allow list for BudgetBackend but is not in the trusted caller set."
                        ).format(agent_name),
                        "fix_type": "mtls-remove",
                        "fix_payload": {"remove_id": sid},
                    }
                )

        if rbac_data:
            default_action = rbac_data.get("default_action", "deny")
            policies = rbac_data.get("policies", [])
            if default_action == "allow":
                hardened_yaml = self.policy_service.build_hardened_rbac_yaml()
                agent_findings = []
                for agent_key, agent in self.policy_service.settings.agents.items():
                    role = (agent.role or "").lower()
                    if "protected" in role or "resource" in role or "mcp server" in role:
                        continue
                    has_rules = any(self.policy_service.is_agent_policy(policy, agent_key) for policy in policies)
                    if not has_rules:
                        finding_id = "rbac-no-rules-{0}".format(agent_key)
                        agent_findings.append(
                            {
                                "id": finding_id,
                                "severity": "MEDIUM",
                                "category": "RBAC",
                                "title": "{0} has unrestricted access".format(agent.name),
                                "description": (
                                    "No RBAC rules are defined for {0}. With default_action=allow, it has broad access."
                                ).format(agent.name),
                                "fix_type": "rbac-policy",
                                "fix_payload": {"yaml": hardened_yaml},
                                "also_fixes": ["rbac-default-allow"],
                            }
                        )
                findings.append(
                    {
                        "id": "rbac-default-allow",
                        "severity": "CRITICAL",
                        "category": "RBAC",
                        "title": "RBAC default action is ALLOW (fail-open)",
                        "description": (
                            "Any mTLS-authenticated agent can access any endpoint on BudgetBackend until explicit rules are added."
                        ),
                        "fix_type": "rbac-policy",
                        "fix_payload": {"yaml": hardened_yaml},
                        "also_fixes": [finding["id"] for finding in agent_findings],
                    }
                )
                findings.extend(agent_findings)

        severity_weights = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5}
        total_deductions = sum(severity_weights.get(finding["severity"], 0) for finding in findings)
        score = max(0, 100 - total_deductions)
        return {
            "score": score,
            "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 50 else "F",
            "findings": findings,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }
