"""Explicit risk observation and sidecar enforcement controls."""

import asyncio
import logging
import time
from copy import deepcopy
from datetime import datetime, timezone
from urllib.parse import quote

import yaml

from ..errors import PortalError

logger = logging.getLogger("isp-portal.services.risk_settings")


class RiskSettingsService:
    def __init__(self, store, graph_client, policy_service):
        self.store = store
        self.graph_client = graph_client
        self.policy_service = policy_service
        self._signal = None
        self._checked_at = 0
        self._lock = asyncio.Lock()
        self._update_lock = asyncio.Lock()

    async def preferences(self):
        try:
            entries = await self.store.list_configs()
        except Exception as exc:
            logger.exception("Risk signal settings could not be read")
            raise PortalError(503, "risk_settings_unavailable", "Risk signal settings could not be read") from exc
        if not entries:
            return {"entra_signal_enabled": True}
        if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict) or type(entries[0].get("entra_signal_enabled")) is not bool:
            raise PortalError(503, "risk_settings_invalid", "Stored risk signal settings are invalid")
        if "risk_enforcement_enabled" in entries[0] and type(entries[0]["risk_enforcement_enabled"]) is not bool:
            raise PortalError(503, "risk_settings_invalid", "Stored risk enforcement settings are invalid")
        if "risk_cache_seconds" in entries[0] and (
            type(entries[0]["risk_cache_seconds"]) is not int or not 0 <= entries[0]["risk_cache_seconds"] <= 9223372036
        ):
            raise PortalError(503, "risk_settings_invalid", "Stored risk cache lifetime is invalid")
        return dict(entries[0])

    async def signal_enabled(self):
        return (await self.preferences())["entra_signal_enabled"]

    async def _save_preferences(self, preferences):
        try:
            await self.store.write_configs([preferences])
        except Exception as exc:
            logger.exception("Risk signal settings could not be saved")
            raise PortalError(503, "risk_settings_write_failed", "Risk signal settings could not be saved") from exc

    async def set_signal_enabled(self, enabled):
        async with self._update_lock:
            preferences = await self.preferences()
            preferences["entra_signal_enabled"] = enabled
            await self._save_preferences(preferences)
        self._signal = None
        logger.warning("Entra agent risk signal explicitly set to %s", enabled)
        return await self.signal_status()

    async def signal_status(self):
        if not await self.signal_enabled():
            return {"enabled": False, "status": "off", "detail": "Portal risk monitoring is off; gateway risk enforcement is controlled separately", "risks": {}}
        async with self._lock:
            if self._signal is not None and time.monotonic() - self._checked_at < 60:
                return self._signal
            checked_at = datetime.now(timezone.utc).isoformat()
            try:
                risks = await self.graph_client.fetch_risky_agents()
                self._signal = {
                    "enabled": True, "status": "on",
                    "detail": "Entra riskyAgents read succeeded ({0} records; absent ratings remain unknown)".format(len(risks)),
                    "checked_at": checked_at, "risks": risks,
                }
            except PortalError as exc:
                logger.warning("Entra agent risk signal unavailable: %s %s", exc.detail, exc.meta)
                body = exc.meta.get("body", "")
                detail = "Entra agent risk signals are temporarily unavailable. Try again later."
                if isinstance(body, str) and "not licensed" in body.lower():
                    detail = "Your tenant is not licensed for this feature."
                elif exc.meta.get("status_code") in (401, 403):
                    detail = "Access to Entra agent risk signals is not permitted. Check your Microsoft Graph permissions."
                self._signal = {
                    "enabled": True, "status": "unavailable", "detail": detail,
                    "checked_at": checked_at, "risks": {}, "error_code": exc.error_code,
                }
            self._checked_at = time.monotonic()
            return self._signal

    async def get_settings(self, request_id):
        async with self._update_lock:
            return await self._get_settings(request_id)

    async def _get_settings(self, request_id):
        signal, policy, health = await asyncio.gather(
            self.signal_status(), self.policy_service.get_policy(request_id),
            self.policy_service.admin_client.get_json("health", request_id),
        )
        governance = policy.get("admin_governance", {})
        preferences = await self.preferences()
        desired = preferences.get("risk_enforcement_enabled")
        seconds = preferences.get("risk_cache_seconds", 90)
        runtime_supported = bool(health.get("entra_risk_enforcement_supported"))
        actual = governance.get("risk_enforcement") != "off"
        cache_changed = runtime_supported and governance.get("risk_cache_seconds", 90) != seconds
        if desired is not None and desired != actual:
            if not health.get("risk_enforcement_control_supported"):
                raise PortalError(409, "sidecar_upgrade_required", "Saved risk settings require the updated sidecar")
            if desired and not governance.get("enabled", False):
                raise PortalError(409, "governance_disabled", "Saved risk enforcement requires enabled admin governance")
            if desired:
                await self._preflight(health, request_id)
            await self._apply_enforcement(desired, policy, request_id, seconds if runtime_supported else None)
            actual = desired
        elif cache_changed:
            await self._apply_enforcement(actual, policy, request_id, seconds)
        return {
            "signal": {key: value for key, value in signal.items() if key != "risks"},
            "risk_enforcement_enabled": governance.get("enabled", False) and actual,
            "enforcement_control_supported": bool(health.get("risk_enforcement_control_supported")),
            "entra_runtime_supported": runtime_supported,
            "risk_cache_seconds": seconds,
            "enforcement_source": "Entra runtime ratings; Security Portal evidence may increase risk but cannot clear Entra risk",
        }

    async def set_enforcement_enabled(self, enabled, request_id):
        health = await self.policy_service.admin_client.get_json("health", request_id)
        if not health.get("risk_enforcement_control_supported"):
            raise PortalError(
                409, "sidecar_upgrade_required",
                "Risk enforcement controls require the updated spiffe-proxy sidecar",
            )
        async with self._update_lock:
            policy = await self.policy_service.get_policy(request_id)
            if enabled and not policy.get("admin_governance", {}).get("enabled", False):
                raise PortalError(409, "governance_disabled", "Enable admin governance in the policy before enabling risk enforcement")
            if enabled:
                await self._preflight(health, request_id)
            previous = await self.preferences()
            preferences = dict(previous)
            preferences["risk_enforcement_enabled"] = enabled
            result = await self._save_and_apply(
                previous, preferences, enabled, policy, request_id,
                preferences.get("risk_cache_seconds", 90) if health.get("entra_risk_enforcement_supported") else None,
            )
        logger.warning("Sidecar risk enforcement explicitly set to %s", enabled)
        return {"risk_enforcement_enabled": enabled, "result": result}

    async def _preflight(self, health, request_id):
        if not health.get("entra_risk_enforcement_supported"):
            raise PortalError(409, "sidecar_upgrade_required", "Update the gateways before enabling Entra runtime risk enforcement")
        control_plane = self.policy_service.get_control_plane_spiffe_id()
        risks, effective = await asyncio.gather(
            self.policy_service.admin_client.get_json("entra-risk?spiffe_id=" + quote(control_plane, safe=""), request_id),
            self.policy_service.admin_client.get_json("ca-policy-effective", request_id),
        )
        risk = risks.get("risks", {}).get(control_plane)
        if not effective.get("ready") or risk not in ("none", "low", "medium", "high") or risk in effective.get("blocked_risk_levels", []):
            raise PortalError(
                409, "risk_enforcement_not_ready",
                "Entra runtime risk enforcement requires available Entra risk evidence and a permitted management identity. Check licensing and Graph access before enabling.",
            )

    async def set_cache_seconds(self, seconds, request_id):
        if type(seconds) is not int or not 0 <= seconds <= 9223372036:
            raise PortalError(422, "risk_cache_invalid", "Enter a non-negative whole number of seconds")
        health = await self.policy_service.admin_client.get_json("health", request_id)
        if not health.get("entra_risk_enforcement_supported"):
            raise PortalError(409, "sidecar_upgrade_required", "Update the gateways before changing the Entra risk cache")
        async with self._update_lock:
            policy = await self.policy_service.get_policy(request_id)
            previous = await self.preferences()
            preferences = dict(previous, risk_cache_seconds=seconds)
            actual = policy.get("admin_governance", {}).get("risk_enforcement") != "off"
            enabled = previous.get("risk_enforcement_enabled", actual)
            if enabled and not actual:
                await self._preflight(health, request_id)
            result = await self._save_and_apply(previous, preferences, enabled, policy, request_id, seconds)
        logger.warning("Gateway Entra risk cache lifetime explicitly set to %s seconds", seconds)
        return {"risk_cache_seconds": seconds, "result": result}

    async def _save_and_apply(self, previous, preferences, enabled, policy, request_id, seconds):
        await self._save_preferences(preferences)
        try:
            return await self._apply_enforcement(enabled, policy, request_id, seconds)
        except PortalError as exc:
            try:
                await self._save_preferences(previous)
            except PortalError as rollback_error:
                raise PortalError(
                    503, "risk_settings_partial_update",
                    "Gateway update failed and the saved preference could not be restored",
                    {"update_error": str(exc), "rollback_error": str(rollback_error)},
                ) from rollback_error
            raise

    async def _apply_enforcement(self, enabled, current_policy, request_id, seconds=None):
        policy = deepcopy(current_policy)
        policy.pop("loaded_at", None)
        policy.pop("request_count", None)
        governance = policy.setdefault("admin_governance", {})
        governance["risk_enforcement"] = "data_plane" if enabled else "off"
        if seconds is not None:
            governance["risk_cache_seconds"] = seconds
        result = await self.policy_service.put_policy(yaml.safe_dump(policy, sort_keys=False), request_id)
        logger.warning("Reconciled sidecar risk enforcement to persisted setting: %s", enabled)
        return result
