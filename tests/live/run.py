#!/usr/bin/env python3
"""Explicit-target live adapter. No discovery, token minting, or tenant writes."""
import argparse
from datetime import datetime
import ipaddress
import json
import math
import multiprocessing
import os
from pathlib import Path
import re
import time
from urllib import parse

from http_transport import NetworkFailure, NoRedirect, exchange, urllib_request, worker

HTTP_WORKER = worker


class Requirement(Exception):
    """A safe, constant prerequisite message."""


class CheckFailure(Exception):
    """A safe, constant assertion message."""


def descriptor(case_id, layer, description, expected, mutation=False):
    return {"id": case_id, "suite": "live", "layer": layer, "profiles": ["live"],
            "description": description, "expected": expected, "mutation": mutation}


def descriptors():
    cases = []
    for short in ("report", "approval"):
        for layer, suffix, expected in (
                ("transport", ".allow", "200 with exact configured SPIFFE identity"),
                ("rbac", ".read.allow", "200 with exact configured SPIFFE identity"),
                ("identity", "", "Exact configured SPIFFE, Entra OID and audience"),
                ("oauth", ".valid", "Fresh unambiguous sidecar audit proves JWT validation")):
            cases.append(descriptor(f"live.{layer}.{short}{suffix}", layer,
                                    f"Seeded budget-{short} reads budget-backend", expected))
    cases.extend([
        descriptor("live.transport.menus.deny", "transport", "Seeded employee-menus transport rejection",
                   "Explicit transport authorization evidence, never an outage"),
        descriptor("live.rbac.report.get-submit.deny", "rbac", "Read-only wrong-method probe of submit path",
                   "403 forbidden correlated to RBAC audit request ID"),
        descriptor("live.rbac.report.submit.deny", "rbac", "Seeded report POST submit denial",
                   "403 RBAC denial; requires safely reversible business fixture", True),
        descriptor("live.rbac.approval.submit.allow", "rbac", "Seeded approval POST submit allowance",
                   "200 submission; requires safely reversible business fixture", True),
    ])
    for target in ("report", "approval", "menus"):
        for token in ("missing-token", "invalid-token"):
            cases.append(descriptor(f"live.a2a.{target}.{token}", "oauth",
                                    f"Direct budget/employee {target} A2A JWT guard",
                                    f"401 JWT {token.replace('-', '_')}"))
    for name, expectation in (("report-to-approval", "allow"),
                              ("menus-to-approval", "deny"), ("report-to-menus", "deny")):
        cases.append(descriptor(f"live.a2a.{name}.{expectation}", "a2a",
                                "Direct target with explicitly supplied workload token",
                                "Validated JWT identity and matching tag" if expectation == "allow"
                                else "Validated JWT identity and nonempty unequal tags"))
    for kind in ("dynamic", "federated"):
        for layer in ("transport", "identity", "oauth"):
            cases.append(descriptor(f"live.{kind}.{layer}", layer,
                                    f"Configured existing {kind} raw-caller fixture",
                                    "Same real read-path evidence as seeded caller; no provisioning"))
    for kind in ("risk", "tag"):
        cases.append(descriptor(f"live.ca.local-{kind}", "conditional_access",
                                f"Exclusive scoped local sidecar {kind} change",
                                "Baseline allows, scoped CA denies, exact snapshot restored", True))
    return cases


CATALOG = {case["id"]: case for case in descriptors()}
ALIASES = {"report": "budget-report", "approval": "budget-approval", "menus": "employee-menus"}
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")


def loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def validate_url(url):
    if not isinstance(url, str) or not url or any(ord(c) <= 32 for c in url) or "\\" in url:
        raise Requirement("Endpoint must be an explicit clean HTTPS or loopback URL")
    try:
        parts = parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise Requirement("Endpoint URL is invalid") from None
    if (not parts.hostname or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment or "%" in parts.netloc
            or "%" in parts.path or ".." in parts.path.split("/")
            or parts.scheme not in ("https", "http")
            or (parts.scheme == "http" and not loopback(parts.hostname))
            or (port is not None and port == 0)):
        raise Requirement("Endpoint must use HTTPS or loopback without credentials, query or traversal")
    if parts.hostname.lower() in {"graph.microsoft.com", "login.microsoftonline.com",
                                   "management.azure.com", "metadata.google.internal"}:
        raise Requirement("Cloud control-plane and identity-provider endpoints are prohibited")
    return url.rstrip("/")


def credential(name):
    if not isinstance(name, str) or not ENV_NAME.fullmatch(name):
        raise Requirement("Credential must reference an environment variable name")
    value = os.environ.get(name, "")
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise Requirement("Required credential environment variable is absent or invalid")
    return value


def settings(config):
    if not isinstance(config, dict) or not isinstance(config.get("live"), dict):
        raise Requirement("Provide explicit config.live endpoints and test identities")
    live = config["live"]
    permitted = {"endpoints", "identities", "admin_key_env", "mutations", "timeout_seconds",
                 "exclusive_observation"}
    if set(live) - permitted:
        raise Requirement("Unknown live configuration field; inline credentials are not accepted")
    for section in ("endpoints", "identities"):
        if not isinstance(live.get(section), dict):
            raise Requirement("Provide explicit live endpoints and identities objects")
    for endpoint in live["endpoints"].values():
        validate_url(endpoint)
    timeout = live.get("timeout_seconds", 20)
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 1 <= timeout <= 60:
        raise Requirement("timeout_seconds must be numeric between 1 and 60")
    return live


def endpoint(live, name):
    return validate_url(live["endpoints"].get(name))


def identity(live, name):
    item = live["identities"].get(name)
    if not isinstance(item, dict) or set(item) - {"spiffe_id", "oid", "audience", "token_env", "invalid_token_env"}:
        raise Requirement("Provide a test identity with environment-name credential references")
    for key in ("spiffe_id", "oid", "audience"):
        if not isinstance(item.get(key), str) or not item[key].strip():
            raise Requirement("Test identity requires explicit SPIFFE ID, OID and audience")
    try:
        sid = parse.urlsplit(item["spiffe_id"])
    except ValueError:
        raise Requirement("Test identity SPIFFE ID is invalid") from None
    if (sid.scheme != "spiffe" or not sid.hostname or not sid.path or sid.query or sid.fragment
            or sid.username is not None or sid.password is not None
            or ".." in sid.path.split("/") or any(ord(c) <= 32 for c in item["spiffe_id"])):
        raise Requirement("Test identity SPIFFE ID is invalid")
    return item


def request(method, url, headers, body=None, timeout=20):
    """Bound DNS, TLS, headers and slow response bodies with a killable worker."""
    # Query strings are constructed only by fixed internal operations, never configuration.
    parts = parse.urlsplit(url)
    validate_url(parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")))
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=HTTP_WORKER, args=(send, (method, url, headers, body, timeout)))
    started = False
    start = time.monotonic()
    try:
        process.start()
        started = True
        send.close()
        if not receive.poll(max(0, timeout - (time.monotonic() - start))):
            raise NetworkFailure("deadline")
        status, data = receive.recv()
        if status is None:
            raise NetworkFailure("request_failed")
        return status, data
    except (OSError, EOFError):
        raise NetworkFailure("request_failed") from None
    finally:
        receive.close()
        send.close()
        if started:
            process.join(0.1)
            if process.is_alive():
                process.terminate()
                process.join(0.5)
            if process.is_alive():
                process.kill()
                process.join(0.5)
        process.close()


def call(live, method, url, headers, body=None):
    status, data = request(method, url, headers, body, timeout=live.get("timeout_seconds", 20))
    if not isinstance(data, dict) or type(status) is not int:
        raise CheckFailure("Response envelope has invalid shape")
    return status, data


def admin(live):
    return {"X-Spiffe-Admin-Key": credential(live.get("admin_key_env")),
            "Content-Type": "application/json"}


def get_management(live, route, local=False):
    base = endpoint(live, "sidecar" if local else "management")
    status, data = call(live, "GET", base + "/" + route, admin(live))
    if status in (401, 403):
        raise Requirement("Management read credentials or permission unavailable")
    if status != 200:
        raise CheckFailure("Management read failed; no enforcement conclusion")
    return data


def raw_call(live, caller, path="/budget/read"):
    status, data = call(live, "POST", endpoint(live, caller) + "/call-backend-raw?" +
                        parse.urlencode({"method": "GET", "path": path}), admin(live))
    if status in (401, 403):
        raise Requirement("Raw caller management authentication failed")
    if status != 200:
        raise CheckFailure("Caller HTTP failure; not a downstream denial")
    if type(data.get("http_status")) is not int:
        raise CheckFailure("Caller response lacks downstream HTTP status")
    return data


def inner(data):
    result = data.get("response")
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except ValueError:
            raise CheckFailure("Downstream response lacks structured enforcement evidence") from None
    if not isinstance(result, dict):
        raise CheckFailure("Downstream response lacks structured enforcement evidence")
    return result


def assert_allowed(data, item, full=False):
    if data.get("http_status") != 200:
        raise CheckFailure("Downstream did not allow the request")
    chain = inner(data).get("identity_chain")
    if not isinstance(chain, dict) or chain.get("spiffe_id") != item["spiffe_id"]:
        raise CheckFailure("Backend did not confirm the configured SPIFFE identity")
    if full:
        token = chain.get("entra_token")
        if (not isinstance(token, dict) or token.get("present") is not True
                or token.get("oid") != item["oid"] or token.get("audience") != item["audience"]
                or chain.get("entra_agent_id") != item["oid"]):
            raise CheckFailure("Identity chain differs from configured Entra identity or audience")


def entries(data):
    result = data.get("entries")
    if not isinstance(result, list) or any(not isinstance(row, dict) for row in result):
        raise CheckFailure("Management audit returned invalid entries")
    if any(not isinstance(row.get("request_id"), str) or not row["request_id"] for row in result):
        raise CheckFailure("Management audit returned invalid correlation IDs")
    return result


def audit_timestamp(row):
    value = row.get("timestamp")
    if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})", value):
        raise Requirement("JWT audit requires valid timezone-qualified event timestamps")
    try:
        return datetime.fromisoformat(value).timestamp()
    except (ValueError, OverflowError):
        raise Requirement("JWT audit requires valid timezone-qualified event timestamps") from None


def audit_continuity(before, after, started):
    before_by_id = {row["request_id"]: row for row in before}
    after_by_id = {row["request_id"]: row for row in after}
    common = before_by_id.keys() & after_by_id.keys()
    if (not common or len(before_by_id) != len(before) or len(after_by_id) != len(after)
            or any(before_by_id[key] != after_by_id[key] for key in common)):
        raise Requirement("JWT audit source continuity requires an immutable retained snapshot anchor")
    if not any(audit_timestamp(before_by_id[key]) <= started for key in common):
        raise Requirement("JWT audit source anchor must predate the observation window")


def read_case(live, caller, layer):
    item = identity(live, caller)
    if layer == "oauth":
        if live.get("exclusive_observation") is not True:
            raise Requirement("JWT audit requires exclusive_observation on a quiescent test caller")
        before_entries = entries(get_management(live, "audit?limit=1000"))
        before = {row["request_id"] for row in before_entries}
        started = time.time()
    data = raw_call(live, caller)
    if layer == "oauth":
        finished = time.time()
    assert_allowed(data, item, full=layer in ("identity", "oauth"))
    if layer == "oauth":
        after_entries = entries(get_management(live, "audit?limit=1000"))
        audit_continuity(before_entries, after_entries, started)
        rows = [row for row in after_entries
                if row.get("request_id") not in before and row.get("request_id")
                and row.get("caller_spiffe_id") == item["spiffe_id"]
                and row.get("method") == "GET" and row.get("path") == "/budget/read"]
        if len(rows) != 1:
            raise Requirement("Need one fresh unambiguous audit entry; concurrent traffic or audit lag")
        row = rows[0]
        if not started <= audit_timestamp(row) <= finished:
            raise Requirement("JWT audit event must fall inside the current request observation window")
        if (row.get("decision") != "allow" or row.get("jwt_valid") is not True
                or row.get("jwt_present") is not True or row.get("jwt_audience") != item["audience"]
                or row.get("enforcement_layer") != "oauth"):
            raise CheckFailure("Sidecar audit did not validate the configured JWT audience")
    return {"identity_matched": True, "jwt_audit_validated": layer == "oauth",
            "audit_source_continuity": layer == "oauth", "audit_window_verified": layer == "oauth"}


def rbac_deny(live):
    item = identity(live, "budget-report")
    data = raw_call(live, "budget-report", "/budget/submit")
    body = inner(data)
    if data["http_status"] != 403 or body.get("error") != "forbidden" or not body.get("request_id"):
        raise CheckFailure("Missing RBAC denial and correlation ID")
    matches = [row for row in entries(get_management(live, "audit?limit=1000"))
               if row.get("request_id") == body["request_id"]]
    if len(matches) != 1:
        raise Requirement("Need correlated RBAC audit entry")
    row = matches[0]
    if (row.get("caller_spiffe_id") != item["spiffe_id"] or row.get("enforcement_layer") != "rbac"
            or row.get("decision") != "deny" or row.get("method") != "GET"
            or row.get("path") != "/budget/submit"):
        raise CheckFailure("Correlated audit does not prove the expected RBAC denial")
    return {"audit_correlated": True, "enforcement_layer": "rbac"}


def a2a(live, case_id):
    tail = case_id.removeprefix("live.a2a.")
    name, outcome = tail.split(".")
    if outcome in ("missing-token", "invalid-token"):
        target = ALIASES[name]
        headers = {}
        if outcome == "invalid-token":
            item = identity(live, target)
            headers["Authorization"] = "Bearer " + credential(item.get("invalid_token_env"))
        status, body = call(live, "GET", endpoint(live, target) + "/a2a/status", headers)
        expected_error = outcome.replace("-", "_")
        if status != 401 or body.get("error") != expected_error or body.get("enforcement_layer") != "jwt":
            raise CheckFailure("Target did not provide the expected JWT authentication denial")
        return {"enforcement_layer": "jwt", "http_status": status}
    caller, target = (ALIASES[x] for x in name.split("-to-"))
    item = identity(live, caller)
    headers = {"Authorization": "Bearer " + credential(item.get("token_env"))}
    status, body = call(live, "GET", endpoint(live, target) + "/a2a/status", headers)
    enforcement = body.get("enforcement")
    if (not isinstance(enforcement, dict) or enforcement.get("jwt_validated") is not True
            or enforcement.get("jwt_oid") != item["oid"]):
        raise CheckFailure("Target did not validate the configured caller JWT")
    if outcome == "allow":
        caller_tag, target_tag = enforcement.get("caller_tag"), enforcement.get("target_tag")
        if (status != 200 or body.get("status") != "ok" or enforcement.get("tag_match") is not True
                or not isinstance(caller_tag, str) or not isinstance(target_tag, str)
                or not caller_tag.strip() or not target_tag.strip()
                or caller_tag.lower() != target_tag.lower()):
            raise CheckFailure("Target did not confirm an allowed tag match")
    elif (status != 403 or body.get("error") != "agent_tag_mismatch"
          or body.get("enforcement_layer") != "conditional_access"
          or enforcement.get("tag_match") is not False
          or not isinstance(body.get("caller_tag"), str) or not isinstance(body.get("target_tag"), str)
          or not body["caller_tag"].strip() or not body["target_tag"].strip()
          or body["caller_tag"].lower() == body["target_tag"].lower()):
        raise CheckFailure("Missing configured tag mismatch; missing Graph data is not proof")
    return {"jwt_validated": True, "tag_match": outcome == "allow", "http_status": status}


def mutation_gate(live):
    item = identity(live, "budget-report")
    flags = live.get("mutations")
    if (not isinstance(flags, dict) or flags.get("enabled") is not True
            or flags.get("environment") != "dedicated-test" or flags.get("exclusive") is not True
            or not isinstance(flags.get("scope_ids"), list)
            or item["spiffe_id"] not in flags["scope_ids"]):
        raise Requirement("Mutation requires dedicated-test, enabled, exclusive and exact scope_ids")
    if credential(flags.get("marker_env")) != "dedicated-test":
        raise Requirement("Dedicated test environment marker must equal dedicated-test")
    base = endpoint(live, "sidecar")
    if not loopback(parse.urlsplit(base).hostname):
        raise Requirement("Mutations are limited to an explicitly configured loopback sidecar")
    admin(live)
    endpoint(live, "budget-report")
    return item


def mutate(live, kind, evidence):
    item = mutation_gate(live)
    collection, field, route = ("risks", "risk_level", "agent-risk") if kind == "risk" else (
        "tags", "tag", "agent-tags")
    sid = item["spiffe_id"]
    snapshot = get_management(live, route, local=True).get(collection)
    if not isinstance(snapshot, dict) or sid not in snapshot:
        raise Requirement("Existing explicit sidecar entry required; API cannot restore absent entries")
    original = snapshot[sid]
    if not isinstance(original, str) or (kind == "risk" and original not in ("low", "medium", "high")):
        raise Requirement("Sidecar snapshot has unsupported value")
    assert_allowed(raw_call(live, "budget-report"), item, full=True)
    changed = "high" if kind == "risk" else "live-harness-deny"
    if original == changed:
        raise Requirement("Fixture is already at the requested denied state")
    url = endpoint(live, "sidecar") + "/" + route
    evidence["cleanup_verified"] = False
    mutation_acknowledged = False
    try:
        status, _ = call(live, "PUT", url, admin(live), {"spiffe_id": sid, field: changed})
        if status != 200:
            raise CheckFailure("Scoped mutation was not acknowledged")
        mutation_acknowledged = True
        state = get_management(live, route, local=True).get(collection)
        if not isinstance(state, dict) or state.get(sid) != changed:
            raise CheckFailure("Scoped mutation readback differs")
        data = raw_call(live, "budget-report")
        body = inner(data)
        reason = "high_risk_agent_blocked" if kind == "risk" else "agent_tag_mismatch"
        if (data["http_status"] != 403 or body.get("layer") != "conditional_access"
                or body.get("error") != reason or body.get("caller") != sid):
            raise CheckFailure("Scoped sidecar CA denial was not observed")
    finally:
        try:
            status, _ = call(live, "PUT", url, admin(live), {"spiffe_id": sid, field: original})
            restored = get_management(live, route, local=True).get(collection)
            if status != 200 or restored != snapshot:
                raise CheckFailure("Cleanup failed: exact sidecar snapshot not restored")
        except (NetworkFailure, Requirement, CheckFailure):
            raise CheckFailure("Cleanup failed: restoration could not be verified") from None
        # A client timeout cannot cancel a server write or order it before restoration.
        if not mutation_acknowledged:
            raise CheckFailure("Cleanup ambiguous: unacknowledged mutation may still complete; "
                               "operator recovery required") from None
        evidence["cleanup_verified"] = True
    assert_allowed(raw_call(live, "budget-report"), item, full=True)
    evidence["post_restore_allowed"] = True


def run_case(case_id, config, profile):
    start = time.monotonic()
    result = dict(CATALOG[case_id])
    evidence = {"source": "live_http"}
    try:
        if profile != "live":
            raise Requirement("Case requires live profile")
        live = settings(config)
        if case_id in {"live.rbac.report.submit.deny", "live.rbac.approval.submit.allow"}:
            raise Requirement("POST submit unsupported: no reversible business snapshot/cleanup API")
        if case_id.startswith("live.ca.local-"):
            mutate(live, case_id.rsplit("-", 1)[1], evidence)
        elif case_id.startswith("live.a2a."):
            evidence.update(a2a(live, case_id))
        elif case_id == "live.transport.menus.deny":
            data = raw_call(live, "employee-menus")
            if data["http_status"] == 200:
                raise CheckFailure("Transport unexpectedly allowed excluded caller")
            if data["http_status"] in (0, 502, 503, 504):
                raise CheckFailure("Transport unavailable; generic failure is not denial evidence")
            raise Requirement("Caller API lacks explicit mTLS rejection telemetry; use protocol suite")
        elif case_id == "live.rbac.report.get-submit.deny":
            evidence.update(rbac_deny(live))
        elif case_id.split(".")[1] in ("dynamic", "federated"):
            _, kind, layer = case_id.split(".")
            evidence.update(read_case(live, kind, layer))
        else:
            _, layer, short, *_ = case_id.split(".")
            evidence.update(read_case(live, ALIASES[short], layer))
        result.update(status="PASS", observed="Expected layer-specific evidence verified")
    except Requirement as exc:
        result.update(status="BLOCKED", observed=str(exc))
    except CheckFailure as exc:
        result.update(status="FAIL", observed=str(exc))
    except NetworkFailure:
        result.update(status="FAIL", observed="HTTP exchange failed; not authorization-denial evidence")
    result.update(evidence=evidence, duration_seconds=round(time.monotonic() - start, 6))
    return result


def run(config, profile):
    return [run_case(case["id"], config, profile) for case in descriptors() if profile in case["profiles"]]


def exit_code(results):
    if any(case["status"] == "FAIL" for case in results):
        return 1
    if any(case["status"] in ("BLOCKED", "SKIPPED") for case in results):
        return 2
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--profile", choices=("local", "live"), default="live")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.list:
        print(json.dumps(descriptors()))
        return 0
    if not args.output:
        parser.error("--output is required when running")
    config = {}
    config_error = False
    if args.config:
        try:
            config = json.loads(args.config.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError):
            config_error = True
    try:
        # Reserve the private destination before any live action or mutation.
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            results = run({} if config_error else config, args.profile)
            if config_error:
                for result in results:
                    result.update(status="BLOCKED", observed="Explicit config file is unreadable or invalid JSON")
            json.dump({"cases": results}, stream, indent=2)
            stream.write("\n")
    except OSError:
        print("Cannot create private output file", file=__import__("sys").stderr)
        return 1
    return exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())
