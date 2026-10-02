"""Dependency-free credential containment and allowlisted report messages."""
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlsplit

OBSERVATIONS = {
    "verified": "Browser assertions and expected HTTP outcomes verified.",
    "config_missing": "Explicit browser portal configuration is missing or invalid.",
    "session_missing": "Session missing; run human-assisted auth setup.",
    "session_invalid": "Session expired, mismatched, malformed, or not private; recapture it.",
    "dependency_missing": "Python browser/runtime dependencies are unavailable.",
    "browser_missing": "Chromium could not launch; install the matching Playwright browser.",
    "auth_disabled": "Live target does not advertise required authentication.",
    "session_rejected": "Saved session was not accepted; human sign-in is required.",
    "assertion_failed": "Browser UI or HTTP assertion did not match the expected outcome.",
    "browser_error": "Browser operation failed; no sensitive error details were retained.",
    "startup_failed": "Local fixture-backed application did not become ready.",
    "inventory_empty": "Security Portal /api/agents returned an empty inventory; "
                       "this does not mean the Azure agent applications are undeployed.",
    "mutation_disabled": "Mutation not enabled for an explicit scoped test resource.",
    "cleanup_failed": "Scoped mutation cleanup failed; operator attention required.",
    "unexpected_error": "Harness execution failed; raw exception details were suppressed.",
    "unsafe_debug": "Unset browser debug and Selenium remote-connection settings before running tests.",
}


def live_origin(value):
    if not isinstance(value, str):
        raise ValueError("invalid origin")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
            parsed.password or parsed.path not in ("", "/") or parsed.query or
            parsed.fragment or any(c.isspace() for c in value)):
        raise ValueError("invalid origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        if parsed.hostname.lower() == "localhost":
            raise ValueError("live origin cannot be loopback")
    else:
        if address.is_loopback or address.is_unspecified:
            raise ValueError("live origin cannot be loopback")
    _ = parsed.port
    return value.rstrip("/")


def validate_debug_environment(environment):
    if any(environment.get(name) for name in (
            "DEBUG", "PWDEBUG", "DEBUG_FILE", "NODE_OPTIONS",
            "SELENIUM_REMOTE_URL", "SELENIUM_REMOTE_HEADERS", "SELENIUM_REMOTE_CAPABILITIES")):
        raise ValueError("unsafe browser debugging environment")


def describe_block(url, reason):
    if reason not in {"child_target", "destination_or_write"}:
        raise ValueError("invalid block reason")
    hostname = urlsplit(url).hostname or "unknown"
    if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", hostname):
        hostname = "unknown"
    return {"hostname": hostname, "reason": reason}


def validate_session(data, *, portal, role, origin):
    if not isinstance(data, dict):
        raise ValueError("invalid session")
    if any(data.get(key) != value for key, value in
           (("version", 1), ("portal", portal), ("role", role), ("origin", origin))):
        raise ValueError("session binding mismatch")
    if portal not in {"management", "security"} or role not in {"admin", "viewer", "unassigned"}:
        raise ValueError("invalid role")
    now = time.time()
    created, expires = data.get("created_at"), data.get("expires_at")
    if any(type(t) not in (int, float) or not math.isfinite(t) for t in (created, expires)):
        raise ValueError("invalid lifetime")
    if not created <= now < expires or not 0 < expires - created <= 86400:
        raise ValueError("expired session")
    session = data.get("session_storage")
    if (not isinstance(session, dict) or not session or
            not all(isinstance(k, str) and isinstance(v, str) for k, v in session.items()) or
            not any("msal" in k.lower() for k in session)):
        raise ValueError("MSAL session storage required")
    state = data.get("storage_state")
    if not isinstance(state, dict) or set(state) != {"cookies", "origins"}:
        raise ValueError("invalid browser storage")
    if not isinstance(state["cookies"], list) or not isinstance(state["origins"], list):
        raise ValueError("invalid browser storage")
    host = urlsplit(origin).hostname
    for cookie in state["cookies"]:
        if not isinstance(cookie, dict) or cookie.get("domain") != host:
            raise ValueError("cross-origin cookie")
    for entry in state["origins"]:
        if (not isinstance(entry, dict) or entry.get("origin") != origin or
                not isinstance(entry.get("localStorage"), list)):
            raise ValueError("cross-origin storage")
        for pair in entry["localStorage"]:
            if (not isinstance(pair, dict) or
                    not all(isinstance(pair.get(k), str) for k in ("name", "value"))):
                raise ValueError("invalid local storage")
    return data


def _reject_symlinks(path):
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("symlink path rejected")


def write_private_json(path, value):
    path = Path(path).absolute()
    _reject_symlinks(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        json.dump(value, handle, allow_nan=False)
        handle.write("\n")


def read_private_json(path):
    path = Path(path).absolute()
    _reject_symlinks(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, encoding="utf-8") as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or
                info.st_uid != os.getuid() or info.st_size > 4_000_000):
            raise ValueError("session file must be private and owner-controlled")
        return json.load(handle)


def case_result(descriptor, status, code, seconds, evidence=None):
    if (status not in {"PASS", "FAIL", "BLOCKED", "SKIPPED"} or code not in OBSERVATIONS or
            type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds < 0):
        raise ValueError("invalid result")
    allowed = {"real_browser", "real_portal_backend", "mocked_identity",
               "mocked_control_plane", "mocked_workload", "pages_checked",
               "http_status", "cleanup_verified"}
    if evidence is not None and (not isinstance(evidence, dict) or
                                not set(evidence) <= allowed or
                                any(type(v) not in (bool, int) for v in evidence.values())):
        raise ValueError("unsafe evidence")
    row = dict(descriptor, status=status, observed=OBSERVATIONS[code],
               duration_seconds=round(seconds, 4))
    if evidence is not None:
        row["evidence"] = evidence
    return row


def allowed_write(path, method, body, *, role, execute_payload=None, saved_name=None,
                  settings_mutation=False):
    try:
        payload = json.loads(body) if body is not None else None
    except (ValueError, TypeError):
        return False
    if role in {"admin", "viewer"} and payload == {} and (path, method) in {
            ("/api/execute", "POST"), ("/set-risk", "PUT"),
            ("/api/settings/risk-signal", "PUT"), ("/api/settings/risk-enforcement", "PUT"),
            ("/api/settings/risk-cache", "PUT")}:
        return True
    if role != "admin":
        return False
    if settings_mutation is True and method == "PUT" and path in {
            "/api/settings/risk-signal", "/api/settings/risk-enforcement"}:
        return isinstance(payload, dict) and set(payload) == {"enabled"} and type(payload["enabled"]) is bool
    if settings_mutation is True and (path, method) == ("/api/settings/risk-cache", "PUT"):
        return (isinstance(payload, dict) and set(payload) == {"seconds"}
                and type(payload["seconds"]) is int and 0 <= payload["seconds"] <= 9223372036)
    if execute_payload and (path, method) == ("/api/execute", "POST"):
        return payload == execute_payload
    if saved_name and re.fullmatch(r"browser-[a-z0-9-]+", saved_name):
        if (path, method) == (f"/api/policy-configs/{saved_name}", "DELETE"):
            return payload is None
        if (path, method) == ("/api/policy-configs", "POST"):
            return isinstance(payload, dict) and payload.get("name") == saved_name
    return False
