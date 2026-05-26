"""
Shared Conditional Access Evaluator for AIM Agent Apps
========================================================
Reads CA policies from Microsoft Graph API and evaluates whether a caller's
risk level should result in denial based on the Entra CA policy's
agentIdRiskLevels condition.

Currently evaluates: agentIdRiskLevels (risk enforcement)
TODO: Evaluate applicationFilter/servicePrincipalFilter (tag enforcement from CA policy)
      This would replace the hardcoded tag matching with CA-policy-driven tag evaluation
      by parsing filter rule expressions like:
        CustomSecurityAttribute.AgentIdentity_Department -eq "Finance"

This module is imported by agent apps (budget-approval, budget-report, etc.)
for direct A2A enforcement — the same enforcement the sidecar performs at
Layer 4b, but here it runs in the target agent's Python process.

Usage:
    from ca_evaluator import CAEvaluator

    evaluator = CAEvaluator()
    blocked, details = await evaluator.should_block_caller(caller_oid)
"""
import os
import time
import logging
from typing import Optional

import httpx

logger = logging.getLogger("ca-evaluator")

GRAPH_CLIENT_ID = os.getenv("GRAPH_CLIENT_ID", "")
GRAPH_CLIENT_SECRET = os.getenv("GRAPH_CLIENT_SECRET", "")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID", "")
GRAPH_BETA = "https://graph.microsoft.com/beta"

# Cache TTLs
CA_POLICY_CACHE_TTL = int(os.getenv("CA_POLICY_CACHE_TTL", "60"))
RISK_CACHE_TTL = int(os.getenv("RISK_CACHE_TTL", "5"))


class CAEvaluator:
    """Evaluates Entra CA policies for agent risk enforcement.

    Caches Graph API responses to avoid excessive calls.
    Thread-safe for use in async FastAPI apps.

    Security model: FAIL CLOSED. If any security lookup fails (Graph
    unavailable, 404, timeout, missing credentials), the decision is DENY.
    Never treat missing data as "safe".
    """

    def __init__(self):
        self._token_cache = {"token": None, "expires_at": 0}  # type: dict
        self._policy_cache = {"policies": None, "fetched_at": 0}  # type: dict
        self._risk_cache = {}  # type: dict
        self._sp_oid_cache = {}  # type: dict

    async def _get_graph_token(self) -> Optional[str]:
        """Acquire Graph API token via client credentials flow."""
        if not GRAPH_CLIENT_ID or not GRAPH_CLIENT_SECRET or not AZURE_TENANT_ID:
            logger.warning("Graph credentials not configured (GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET, AZURE_TENANT_ID)")
            return None

        now = time.time()
        if self._token_cache["token"] and self._token_cache["expires_at"] > now + 60:
            return self._token_cache["token"]

        token_url = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token"
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(token_url, data={
                "client_id": GRAPH_CLIENT_ID,
                "client_secret": GRAPH_CLIENT_SECRET,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            })
            if resp.status_code == 200:
                data = resp.json()
                self._token_cache["token"] = data["access_token"]
                self._token_cache["expires_at"] = now + data.get("expires_in", 3600)
                return data["access_token"]
            logger.error(f"Graph token acquisition failed: {resp.status_code}")
            return None

    async def _resolve_sp_object_id(self, app_id: str) -> Optional[str]:
        """Resolve an appId (client ID) to the service principal's object ID.

        The riskyAgents API is indexed by SP object ID, not appId.
        JWT oid claims contain the appId, so we must resolve before querying risk.
        Results are cached since the mapping is stable.
        """
        if app_id in self._sp_oid_cache:
            return self._sp_oid_cache[app_id]

        token = await self._get_graph_token()
        if not token:
            return None

        url = (
            "https://graph.microsoft.com/v1.0/servicePrincipals"
            f"?$filter=appId eq '{app_id}'&$select=id,displayName"
        )
        headers = {"Authorization": f"Bearer {token}", "ConsistencyLevel": "eventual"}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("value"):
                        sp_oid = data["value"][0]["id"]
                        display = data["value"][0].get("displayName", "")
                        logger.info(f"Resolved appId {app_id} -> SP OID {sp_oid} ({display})")
                        self._sp_oid_cache[app_id] = sp_oid
                        return sp_oid
                logger.warning(f"SP lookup for appId {app_id} returned {resp.status_code}")
        except Exception as e:
            logger.warning(f"SP lookup failed for appId {app_id}: {e}")
        return None

    async def fetch_ca_policies(self) -> list[dict]:
        """Fetch CA policies from Graph that have agentIdRiskLevels conditions.

        Returns list of parsed CA policies. Cached for CA_POLICY_CACHE_TTL seconds.
        """
        now = time.time()
        if (self._policy_cache["policies"] is not None
                and now - self._policy_cache["fetched_at"] < CA_POLICY_CACHE_TTL):
            return self._policy_cache["policies"]

        token = await self._get_graph_token()
        if not token:
            logger.debug("Graph credentials not configured — CA policy fetch skipped")
            return self._policy_cache.get("policies") or []

        headers = {"Authorization": f"Bearer {token}"}
        # Fetch all CA policies (no $filter — Graph beta rejects OR expressions).
        # Filter client-side to enabled + report-only policies with agentIdRiskLevels.
        url = f"{GRAPH_BETA}/identity/conditionalAccess/policies"

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    all_policies = resp.json().get("value", [])
                    # Filter client-side: only enabled/report-only policies with agentIdRiskLevels
                    risk_policies = []
                    for p in all_policies:
                        state = p.get("state", "")
                        if state not in ("enabled", "enabledForReportingButNotEnforced"):
                            continue
                        conditions = p.get("conditions", {})
                        risk_levels = conditions.get("agentIdRiskLevels")
                        if risk_levels:
                            risk_policies.append(p)
                    self._policy_cache["policies"] = risk_policies
                    self._policy_cache["fetched_at"] = now
                    logger.info(f"Fetched {len(risk_policies)} CA policies with agentIdRiskLevels")
                    return risk_policies
                else:
                    logger.warning(f"CA policy fetch failed: {resp.status_code}")
                    return self._policy_cache.get("policies") or []
        except Exception as e:
            logger.error(f"CA policy fetch error: {e}")
            return self._policy_cache.get("policies") or []

    async def fetch_agent_risk(self, agent_oid: str) -> Optional[str]:
        """Fetch agent risk level from Entra ID Protection riskyAgents API.

        The agent_oid may be an appId (from JWT oid claim). This method resolves
        it to the SP object ID first, since riskyAgents is indexed by SP OID.

        Returns riskLevel string ("high", "medium", "low", "none") or None on
        error. FAIL CLOSED: None means "could not determine risk" and the
        caller must treat it as a block, not as safe.
        """
        # Resolve appId to SP object ID
        sp_oid = await self._resolve_sp_object_id(agent_oid)
        if not sp_oid:
            logger.error(f"Cannot resolve appId {agent_oid} to SP OID — fail closed")
            return None  # Caller must treat None as DENY

        now = time.time()
        cached = self._risk_cache.get(sp_oid)
        if cached and now - cached["fetched_at"] < RISK_CACHE_TTL:
            return cached["risk"]

        token = await self._get_graph_token()
        if not token:
            logger.error("Graph token unavailable for risk lookup — fail closed")
            return None  # Caller must treat None as DENY

        headers = {"Authorization": f"Bearer {token}"}
        url = f"{GRAPH_BETA}/identityProtection/riskyAgents/{sp_oid}"

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    risk_level = data.get("riskLevel", "none")
                    risk_state = data.get("riskState", "unknown")
                    # confirmedSafe with riskLevel=none means agent was explicitly cleared
                    if risk_state == "confirmedSafe" or risk_level == "none":
                        risk_level = "none"
                    self._risk_cache[sp_oid] = {"risk": risk_level, "fetched_at": now}
                    logger.info(f"Risk for SP {sp_oid}: {risk_level} (state={risk_state})")
                    return risk_level
                elif resp.status_code == 404:
                    # Agent not in riskyAgents collection = not at risk
                    # This is safe ONLY because we resolved to a valid SP OID first.
                    # If the SP OID was wrong, _resolve_sp_object_id would have failed.
                    self._risk_cache[sp_oid] = {"risk": "none", "fetched_at": now}
                    logger.info(f"SP {sp_oid} not in riskyAgents (404) — no risk")
                    return "none"
                else:
                    logger.error(f"riskyAgents fetch for SP {sp_oid}: unexpected {resp.status_code} — fail closed")
                    return None  # Fail closed
        except Exception as e:
            logger.error(f"riskyAgents fetch error for SP {sp_oid}: {e} — fail closed")
            return None  # Fail closed

    def get_blocked_risk_levels(self, policies: list[dict]) -> list[str]:
        """Extract the set of risk levels that should be blocked from CA policies.

        A risk level is blocked if ANY policy has:
        - agentIdRiskLevels containing that level
        - grantControls.builtInControls containing "block"
        - state is "enabled" (not report-only)

        For report-only policies, log the evaluation but don't block.
        Returns list of risk level strings (e.g., ["high"]).
        """
        blocked = set()
        for policy in policies:
            grant = policy.get("grantControls", {})
            controls = grant.get("builtInControls", [])
            if "block" not in controls:
                continue

            state = policy.get("state", "")
            conditions = policy.get("conditions", {})
            risk_levels = conditions.get("agentIdRiskLevels", [])

            if isinstance(risk_levels, str):
                risk_levels = [risk_levels]

            if state == "enabled":
                blocked.update(risk_levels)
            elif state == "enabledForReportingButNotEnforced":
                for level in risk_levels:
                    logger.info(
                        f"[CA report-only] Policy '{policy.get('displayName')}' "
                        f"would block risk level '{level}' (report-only mode)"
                    )

        return list(blocked)

    async def should_block_caller(
        self,
        caller_oid: str,
        fallback_risk: Optional[str] = None,
    ) -> tuple:
        """Evaluate whether a caller should be blocked based on Entra CA policies.

        FAIL CLOSED: If Graph credentials are missing, Graph is unreachable, or
        risk lookup fails, the caller IS blocked. This is a security PoC —
        silent bypass of enforcement is never acceptable.

        Args:
            caller_oid: The Entra agent identity OID (appId) of the caller.
            fallback_risk: IGNORED — kept for API compat but Entra is sole source.

        Returns:
            (blocked: bool, details: dict) where details includes enforcement info.
        """
        details = {
            "enforcement_source": "entra_ca_policy",
            "caller_oid": caller_oid,
        }  # type: dict

        # FAIL CLOSED: If Graph credentials are not configured, DENY
        if not GRAPH_CLIENT_ID or not GRAPH_CLIENT_SECRET or not AZURE_TENANT_ID:
            details["enforcement_source"] = "fail_closed"
            details["reason"] = "Graph credentials not configured — DENY (fail closed)"
            details["agent_risk"] = "unknown"
            details["risk_source"] = "unavailable"
            return True, details

        # Fetch CA policies
        policies = await self.fetch_ca_policies()
        if not policies:
            # FAIL CLOSED: Can't read CA policies = DENY
            details["enforcement_source"] = "fail_closed"
            details["reason"] = "Cannot read CA policies from Graph — DENY (fail closed)"
            details["agent_risk"] = "unknown"
            details["risk_source"] = "unavailable"
            return True, details

        # Get blocked risk levels from CA policy
        blocked_levels = self.get_blocked_risk_levels(policies)
        details["blocked_risk_levels"] = blocked_levels
        details["ca_policy_count"] = len(policies)
        details["ca_policy_ids"] = [p.get("id") for p in policies]

        if not blocked_levels:
            details["reason"] = "CA policies exist but no risk levels are actively blocked"
            details["agent_risk"] = "n/a"
            details["risk_source"] = "entra_ca_policy"
            return False, details

        # Fetch caller's risk from Entra ID Protection (resolves appId -> SP OID)
        caller_risk = await self.fetch_agent_risk(caller_oid)

        if caller_risk is None:
            # FAIL CLOSED: Can't determine risk = DENY
            details["enforcement_source"] = "fail_closed"
            details["reason"] = "Cannot determine caller risk from Entra — DENY (fail closed)"
            details["agent_risk"] = "unknown"
            details["risk_source"] = "unavailable"
            details["enforcement_layer"] = "conditional_access"
            return True, details

        details["agent_risk"] = caller_risk
        details["risk_source"] = "entra_id_protection"

        # Evaluate
        if caller_risk in blocked_levels:
            details["reason"] = "high_risk_agent_blocked"
            details["enforcement_layer"] = "conditional_access"
            return True, details

        details["reason"] = "risk_level_not_blocked"
        return False, details


# Module-level singleton for use by agent apps
_evaluator: Optional[CAEvaluator] = None


def get_evaluator() -> CAEvaluator:
    """Get or create the module-level CAEvaluator singleton."""
    global _evaluator
    if _evaluator is None:
        _evaluator = CAEvaluator()
    return _evaluator
