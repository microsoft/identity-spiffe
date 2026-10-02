#!/usr/bin/env python3
"""Unattended local gate: self-tests once, then fresh complete local matrices."""

import argparse
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import unittest
import uuid

from browser import browser_guards
from processes import owned_process, ProcessCleanupError, ProcessLaunchError
import runner


ROOT = Path(__file__).resolve().parent
SCRIPT = Path(__file__).resolve()
GROUPS = (
    ("runner", ".", "test_runner.py"),
    ("check", ".", "test_check.py"),
    ("processes", ".", "test_processes.py"),
    ("browser", "browser", "test_*.py"),
    ("browser-regressions", "browser/regressions", "test_*.py"),
    ("protocols", "protocols", "test_*.py"),
    ("live", "live", "test_*.py"),
    ("stack", "stack", "test_*.py"),
    ("e2e", "e2e", "test_*.py"),
)
UNIT_COUNTS = (
    "discovered", "tests", "failures", "errors", "skipped",
    "expected_failures", "unexpected_successes", "missing_dependencies",
)
DESCRIPTORS = ("id", "suite", "profiles", "layer", "description", "expected", "mutation")
SOURCE_PATHS = ("tests", "portal", "securityportal-mock", "src", "config", "configs")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_path(path):
    path = path.absolute()
    require(".." not in path.parts, "Parent traversal is not accepted")
    require(not any(p.is_symlink() for p in (path, *path.parents)), "Symlink path rejected")
    return path


class UnsafeOutputError(ValueError):
    pass


def artifact_output(path):
    """Untracked in-checkout artifacts would invalidate whole-worktree provenance."""
    path = safe_path(path)
    checkout = runner.ROOT.parent.resolve()
    if path.is_relative_to(checkout):
        relative = path.relative_to(checkout).as_posix()
        try:
            tracked = subprocess.run(
                ["git", "ls-files", "-z", "--cached", "--with-tree=HEAD", "--",
                 ":(literal)" + relative],
                cwd=checkout, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=10, check=False,
            )
            ignored = subprocess.run(
                ["git", "check-ignore", "--quiet", "--", relative + "/"],
                cwd=checkout, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise UnsafeOutputError from None
        if tracked.returncode != 0 or tracked.stdout or ignored.returncode != 0:
            raise UnsafeOutputError
    return path


def prepare_output(path):
    previous = os.umask(0o077)
    try:
        return runner.prepare_output(safe_path(path))
    finally:
        os.umask(previous)


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON field")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise ValueError("Nonfinite JSON number")

    path = safe_path(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 16 * 1024 * 1024,
                "Report must be a bounded regular file")
        return json.load(stream, object_pairs_hook=pairs, parse_constant=invalid_constant)


def selftest_groups(root):
    return [
        group for group in GROUPS
        if (group[0] not in ("stack", "e2e") or (root / group[1]).is_dir())
        and (group[0] != "processes" or (root / group[2]).is_file())
    ]


def unit_exit(counts):
    if counts["failures"] or counts["unexpected_successes"] or (
        counts["errors"] > counts["missing_dependencies"]
    ):
        return 1
    if (counts["errors"] or counts["skipped"] or counts["expected_failures"]
            or not counts["tests"] or counts["tests"] != counts["discovered"]):
        return 2
    return 0


def run_unittests(start, pattern, output, group):
    """A child-only entry point: stdlib results, never parsed console banners."""
    class Result(unittest.TestResult):
        missing_dependencies = 0

        def addError(self, test, err):
            if issubclass(err[0], ImportError):
                self.missing_dependencies += 1
            super().addError(test, err)

    counts = dict.fromkeys(UNIT_COUNTS, 0)
    blocked_environment = False
    try:
        browser_guards.validate_debug_environment(os.environ)
    except ValueError:
        blocked_environment = True
    with open(os.devnull, "w") as sink, redirect_stdout(sink), redirect_stderr(sink):
        try:
            loader = unittest.TestLoader()
            suite = (unittest.TestSuite() if blocked_environment
                     else loader.discover(str(start), pattern=pattern))
            counts["discovered"] = suite.countTestCases()
            result = Result()
            suite.run(result)
            counts.update(
                tests=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                skipped=len(result.skipped), expected_failures=len(result.expectedFailures),
                unexpected_successes=len(result.unexpectedSuccesses),
                missing_dependencies=result.missing_dependencies,
            )
        except ImportError:
            counts.update(errors=1, missing_dependencies=1)
        except Exception:
            counts.update(errors=1)
    code = unit_exit(counts)
    runner.private_write(safe_path(output), json.dumps({
        "schema_version": 1, "kind": "unittest", "group": group,
        "counts": counts, "exit_code": code,
        "blocked_reason": "unsafe_browser_environment" if blocked_environment else None,
    }, indent=2) + "\n")
    return code


def run_command(command, cwd, timeout, *, env=None, stdout=subprocess.DEVNULL, registry_base=None):
    start = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()
    environment = dict(os.environ if env is None else env, IDENTITY_TEST_INHERIT_PROCESS_GROUP="1")
    result = {"returncode": None, "timed_out": False, "launch_error": False, "cleanup_error": False,
              "cleanup_scope": "registry"}
    process = None
    try:
        with owned_process(
            command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=subprocess.DEVNULL, registry_base=registry_base,
            **({"umask": 0o077} if os.name == "posix" else {}),
        ) as process:
            result["process_registry"] = process.identity_process_registry
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
            except KeyboardInterrupt:
                result["interrupted"] = True
    except ProcessCleanupError:
        result["cleanup_error"] = True
    except ProcessLaunchError:
        result["launch_error"] = True
    except (OSError, subprocess.TimeoutExpired):
        result["launch_error" if process is None else "cleanup_error"] = True
    finally:
        if process is not None:
            result["returncode"] = process.returncode
    result["duration_seconds"] = round(time.monotonic() - start, 3)
    result.update(started_at=started_at, finished_at=datetime.now(timezone.utc).isoformat())
    return result


def command_step(step_id, command, cwd, timeout, **kwargs):
    result = run_command(command, cwd, timeout, **kwargs)
    step = {
        "id": step_id, "command": command, **result,
        "status": "PASS", "detail": "", "counts": {}, "reports": {},
    }
    if result.get("cleanup_error"):
        step.update(status="FAIL", detail="Process group cleanup failed; inspect the private run before retrying")
    elif result["launch_error"]:
        step.update(status="BLOCKED", detail="Command could not start; verify the prepared runtime")
    elif result["timed_out"] or result.get("interrupted"):
        step.update(status="FAIL", detail="Command interrupted or timed out; owned processes terminated")
    return step


def validate_unit(report, group, returncode):
    require(isinstance(report, dict) and type(report.get("schema_version")) is int
            and report["schema_version"] == 1 and report.get("kind") == "unittest"
            and report.get("group") == group, "Invalid unittest report schema")
    counts = report.get("counts")
    require(isinstance(counts, dict) and set(counts) == set(UNIT_COUNTS),
            "Missing unittest counts")
    require(all(type(n) is int and 0 <= n <= 10**7 for n in counts.values()),
            "Invalid unittest count")
    require(counts["tests"] <= counts["discovered"], "Executed count exceeds discovered tests")
    require(counts["missing_dependencies"] <= counts["errors"], "Invalid dependency error count")
    require(type(report.get("exit_code")) is int
            and report["exit_code"] == returncode == unit_exit(counts),
            "Unittest exit code disagrees with structured results")
    return counts


def matrix_snapshot(report):
    if not isinstance(report, dict) or not isinstance(report.get("cases"), list):
        return None
    rows = report["cases"]
    if not rows or any(not isinstance(c, dict) or not isinstance(c.get("id"), str)
                       or c.get("status") not in runner.STATUSES for c in rows):
        return None
    mapping = {c["id"]: c["status"] for c in rows}
    return mapping if len(mapping) == len(rows) else None


def validate_report(inventory, report, returncode):
    require(isinstance(report, dict), "Missing matrix object")
    require(type(report.get("schema_version")) is int and report["schema_version"] == 1
            and report.get("profile") == "local", "Invalid matrix version or profile")
    require(isinstance(report.get("run_id"), str) and bool(report["run_id"].strip()),
            "Missing run ID")
    require(isinstance(report.get("created_at"), str), "Missing creation time")
    require(datetime.fromisoformat(report["created_at"]).tzinfo is not None, "Missing time zone")
    rows = runner.validate_matrix(report.get("cases"))
    expected = {c["id"]: c for c in inventory}
    require({c["id"] for c in rows} == set(expected), "Matrix IDs disagree with inventory")
    for case in rows:
        require(all(case.get(key) == expected[case["id"]].get(key) for key in DESCRIPTORS),
                "Matrix descriptors disagree with inventory")
        duration = case.get("duration_seconds")
        require(case.get("status") in runner.STATUSES and isinstance(case.get("observed"), str)
                and type(duration) in (int, float) and 0 <= duration <= 2147483647
                and math.isfinite(duration), "Invalid matrix outcome")
        if "local" not in case["profiles"]:
            require(case["status"] == "NOT_RUN", "Matrix executed outside the local profile")
        else:
            require(case["suite"] != "live" and case["status"] != "NOT_RUN",
                    "A local case was not executed or belongs to the live suite")
    counts = {status: sum(c["status"] == status for c in rows) for status in runner.STATUSES}
    require(isinstance(report.get("summary"), dict)
            and all(type(n) is int for n in report["summary"].values())
            and report["summary"] == counts, "Matrix summary disagrees with outcomes")
    metadata = report.get("metadata")
    require(isinstance(metadata, dict)
            and metadata.get("selected_suites") == list(runner.SUITES)
            and type(metadata.get("selected_count")) is int
            and metadata["selected_count"] == sum("local" in c["profiles"] for c in inventory)
            and isinstance(metadata.get("python_version"), str), "Invalid matrix selection metadata")
    require(type(report.get("exit_code")) is int
            and report["exit_code"] == returncode == runner.exit_code(rows),
            "Matrix exit code disagrees with outcomes")
    json.dumps(report, allow_nan=False)
    return counts


def source_digest(root=None):
    """Hash Git-visible runtime/test sources, never ignored state or artifacts."""
    root = runner.ROOT.parent if root is None else root
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", *SOURCE_PATHS],
        cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=10, check=False,
    )
    require(listed.returncode == 0 and listed.stdout, "Source inventory unavailable")
    digest = hashlib.sha256()
    size = 0
    for name in sorted(set(listed.stdout.split(b"\0")) - {b""}):
        relative = Path(os.fsdecode(name))
        if any(part in (".auth", ".work") for part in relative.parts):
            continue
        path = safe_path(root / relative)
        require(path.is_relative_to(root), "Source path is outside the checkout")
        digest.update(name + b"\0")
        if not path.exists():
            digest.update(b"deleted\0")
            continue
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            size += info.st_size
            require(stat.S_ISREG(info.st_mode) and size <= 128 * 1024 * 1024,
                    "Source fingerprint requires bounded regular files")
            digest.update(hashlib.file_digest(stream, "sha256").digest())
    return digest.hexdigest()


def source_metadata():
    metadata = {**runner.git_metadata(), "source_scope": list(SOURCE_PATHS)}
    try:
        metadata["source_digest"] = source_digest()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        metadata["source_digest"] = None
    return metadata


def validate_invocation(report, step, source, seen_ids):
    require(isinstance(report, dict) and isinstance(report.get("created_at"), str),
            "Missing matrix creation time")
    created = datetime.fromisoformat(report["created_at"])
    started = datetime.fromisoformat(step["started_at"])
    finished = datetime.fromisoformat(step["finished_at"])
    require(created.tzinfo is not None and started <= created <= finished,
            "Matrix is outside this invocation's UTC time window")
    run_id = report.get("run_id")
    require(isinstance(run_id, str) and bool(run_id.strip()) and run_id not in seen_ids,
            "Missing or reused matrix run ID")
    metadata = report.get("metadata")
    require(isinstance(metadata, dict)
            and type(metadata.get("worktree_dirty")) is bool
            and all(metadata.get(key) == source[key] for key in ("source_commit", "worktree_dirty")),
            "Matrix source does not match the gate snapshot")
    require(source_metadata() == source, "Runtime/test source changed during the gate")
    seen_ids.add(run_id)


def stability(snapshots):
    available = [s for s in snapshots if s is not None]
    ids = sorted(set().union(*(set(s) for s in available))) if available else []
    changes = {
        runner.redact(case_id): [s.get(case_id, "MISSING") for s in available]
        for case_id in ids if len({s.get(case_id, "MISSING") for s in available}) > 1
    }
    stable_failures = [
        runner.redact(case_id) for case_id in ids if len(available) == len(snapshots) >= 2
        and all(s.get(case_id) == "FAIL" for s in available)
    ]
    state = "STABLE"
    if changes:
        state = "UNSTABLE"
    elif len(available) != len(snapshots) or len(available) < 2:
        state = "INCOMPLETE"
    elif stable_failures:
        state = "REPRODUCIBLE_FAILURE"
    return {"status": state, "changes": changes, "stable_failures": stable_failures}


def write_summary(directory, steps, snapshots, repeat, source):
    repeated = stability(snapshots)
    failed = any(s["status"] == "FAIL" for s in steps) or repeated["status"] == "UNSTABLE"
    incomplete = any(s["status"] != "PASS" for s in steps) or repeated["status"] == "INCOMPLETE"
    code = 1 if failed else 2 if incomplete else 0
    report = runner.redact({
        "schema_version": 1, "profile": "local", "repeat": repeat,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "metadata": {**source, "python_version": sys.version.split()[0]},
        "reports": {"json": str(directory / "check.json"), "markdown": str(directory / "check.md")},
        "status": {0: "READY", 1: "FAIL", 2: "INCOMPLETE"}[code],
        "exit_code": code, "steps": steps, "stability": repeated,
        "scope": "Local evidence only. No live sign-in, deployment or cloud mutations. "
                 "Local E2E fixture changes are restored by their owning suites. "
                 "Stable failures are not an accepted passing baseline.",
    })
    runner.private_write(directory / "check.json", json.dumps(report, indent=2, allow_nan=False) + "\n")
    lines = [
        "# Unattended local check", "",
        f"Verdict: **{report['status']}** | Exit: **{code}** | Repeats: **{repeat}**",
        "Source: " + runner.markdown_cell(report["metadata"]["source_commit"])
        + " | Dirty worktree: " + str(report["metadata"]["worktree_dirty"]),
        f"Repeatability: **{repeated['status']}**", "", report["scope"], "",
        "READY requires every self-test and selected case to pass, with zero skips.",
        "NOT_RUN live cases are excluded from readiness, not counted as verified.", "",
        "| Step | Status | Exit / seconds | Counts | Detail | Reports |",
        "|---|---|---|---|---|---|",
    ]
    for step in report["steps"]:
        cells = [
            step["id"], step["status"],
            f"{step.get('returncode', '—')} / {step.get('duration_seconds', '—')}",
            ", ".join(f"{k}={v}" for k, v in step["counts"].items()), step["detail"],
        ]
        links = " ".join(f"[{key}]({path})" for key, path in step["reports"].items())
        lines.append("| " + " | ".join(runner.markdown_cell(c) for c in cells) + " | " + links + " |")
        for case in step.get("failed_cases", []):
            lines.append("\n- " + " | ".join(runner.markdown_cell(case[k])
                                           for k in ("id", "status", "expected", "observed")))
    if repeated["changes"]:
        lines += ["", "Changed IDs/statuses (no last-run-wins):"]
        lines += ["- " + runner.markdown_cell(key) + ": " + " → ".join(values)
                  for key, values in repeated["changes"].items()]
    runner.private_write(directory / "check.md", "\n".join(lines) + "\n")
    return report


def finish(directory, steps, snapshots, repeat, source):
    report = write_summary(directory, steps, snapshots, repeat, source)
    print(f"{report['status']}: local check; stability={report['stability']['status']}; "
          f"exit={report['exit_code']}")
    print(runner.redact("Reports: " + str(directory / "check.md") + " and " + str(directory / "check.json")))
    return report["exit_code"]


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("Invalid check arguments; use --help for supported options")


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=2, help="Fresh local runs (2-10; default 2)")
    parser.add_argument("--timeout", type=int, default=1800, help="Per-command seconds (1-3600)")
    parser.add_argument("--output", type=Path,
                        help="New private directory outside the checkout or Git-ignored "
                             "(default tests/artifacts/check-*)")
    parser.add_argument("--_unit", help=argparse.SUPPRESS)
    parser.add_argument("--_start", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--_pattern", help=argparse.SUPPRESS)
    try:
        args = parser.parse_args(argv)
        if args._unit:
            require(args._start is not None and args._pattern is not None and args.output is not None,
                    "Missing child unittest arguments")
            return run_unittests(args._start, args._pattern, args.output, args._unit)
        require(2 <= args.repeat <= 10 and 1 <= args.timeout <= 3600, "Invalid repeat/timeout bounds")
        run_id = datetime.now(timezone.utc).strftime("check-%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
        directory = prepare_output(artifact_output(args.output or ROOT / "artifacts" / run_id))
        scratch = directory / "scratch"
        scratch.mkdir(mode=0o700)
    except UnsafeOutputError:
        print("INCOMPLETE: output provenance is unavailable or unsafe. Use a new directory "
              "outside the checkout or a Git-ignored directory with no tracked files, "
              "such as --output tests/artifacts/<new-name>.", file=sys.stderr)
        return 2
    except (OSError, ValueError):
        print("INCOMPLETE: invalid arguments or output path; use --help and a new nonsymlink directory.",
              file=sys.stderr)
        return 2

    environment_step = {
        "id": "environment", "status": "PASS",
        "detail": "Shared browser debug/remote-connection environment guard accepted",
        "counts": {}, "reports": {},
    }
    try:
        browser_guards.validate_debug_environment(os.environ)
    except ValueError:
        environment_step.update(status="BLOCKED", detail=browser_guards.OBSERVATIONS["unsafe_debug"])
        return finish(directory, [environment_step], [None] * args.repeat, args.repeat, {
            "source_commit": "not-inspected", "worktree_dirty": None,
            "source_digest": None, "source_scope": [],
        })
    env = {**os.environ, "TMPDIR": str(scratch), "TMP": str(scratch), "TEMP": str(scratch),
           "IDENTITY_TEST_INHERIT_PROCESS_GROUP": "1"}
    registry_base = scratch if scratch.is_relative_to(SCRIPT.parent / "artifacts") else None
    source = source_metadata()
    source_ready = (isinstance(source["source_commit"], str)
                    and source["source_commit"] not in ("", "unavailable")
                    and type(source["worktree_dirty"]) is bool
                    and source["source_digest"] is not None)
    steps = [environment_step, {
        "id": "source", "status": "PASS" if source_ready else "BLOCKED",
        "detail": "Source commit, worktree state and runtime/test source digest captured before execution",
        "counts": {}, "reports": {},
    }]
    snapshots, seen_ids = [], set()
    inventory = None
    capture = directory / "inventory.raw"
    try:
        fd = os.open(capture, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            step = command_step("inventory", [sys.executable, str(ROOT / "run.py"), "--list"],
                                ROOT.parent, min(args.timeout, 120), env=env, stdout=stream,
                                registry_base=registry_base)
        if step["status"] == "PASS":
            if step["returncode"] != 0:
                step.update(status="BLOCKED", detail="Inventory command failed; verify suite prerequisites")
            else:
                inventory = runner.validate_matrix(read_json(capture))
                require(any("local" in c["profiles"] for c in inventory), "Empty local inventory")
                require(not any(c["suite"] == "live" and "local" in c["profiles"] for c in inventory),
                        "Live cases cannot be selected by this gate")
                step["counts"] = dict(Counter(c["suite"] for c in inventory))
                runner.private_write(directory / "inventory.json",
                                     json.dumps(runner.redact(inventory), indent=2) + "\n")
                step["reports"] = {"json": "inventory.json"}
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        inventory = None
        step = locals().get("step", {
            "id": "inventory", "command": [], "counts": {}, "reports": {},
        })
        step.update(status="FAIL", detail="Inventory is absent, empty or invalid")
    finally:
        if capture.exists() or capture.is_symlink():
            capture.unlink()
    steps.append(step)
    e2e = inventory and any(c["suite"] == "e2e" and "local" in c["profiles"] for c in inventory)
    steps.append({
        "id": "coverage.e2e", "status": "PASS" if e2e and (ROOT / "e2e" / "run.py").is_file() else "BLOCKED",
        "detail": "Connected E2E must be present in the local inventory and on disk",
        "counts": {}, "reports": {},
    })

    for name, relative, pattern in selftest_groups(ROOT):
        output = directory / ("unit-" + name + ".json")
        command = [sys.executable, str(SCRIPT), "--_unit", name, "--_start", str(ROOT / relative),
                   "--_pattern", pattern, "--output", str(output)]
        step = command_step("unit." + name, command, ROOT.parent, args.timeout,
                            env=env, registry_base=registry_base)
        try:
            if step["status"] == "PASS":
                counts = validate_unit(read_json(output), name, step["returncode"])
                step["counts"] = counts
                step["reports"] = {"json": output.name}
                code = unit_exit(counts)
                step["status"] = "PASS" if code == 0 else "FAIL" if code == 1 else (
                    "BLOCKED" if counts["missing_dependencies"] else "INCOMPLETE")
                step["detail"] = "Structured unittest results; skipped/expected failures are incomplete"
        except (OSError, ValueError, TypeError, OverflowError, RecursionError):
            step.update(status="FAIL", detail="Unittest report missing, malformed or inconsistent with exit")
        steps.append(step)

    for index in range(1, args.repeat + 1):
        name = f"run-{index}"
        command = [sys.executable, str(ROOT / "run.py"), "--profile", "local",
                   "--output", str(directory / name),
                   "--timeout", str(max(1, args.timeout // len(runner.SUITES)))]
        if inventory is None or not source_ready:
            steps.append({"id": name, "status": "BLOCKED", "command": command,
                          "detail": "Not launched without valid inventory and source provenance",
                          "counts": {}, "reports": {}})
            snapshots.append(None)
            continue
        step = command_step(name, command, ROOT.parent, args.timeout, env=env, registry_base=registry_base)
        snapshot = None
        try:
            if step["status"] == "PASS":
                report = read_json(directory / name / "matrix.json")
                validate_invocation(report, step, source, seen_ids)
                step["run_id"] = report["run_id"]
                snapshot = matrix_snapshot(report)
                counts = validate_report(inventory, report, step["returncode"])
                safe_path(directory / name / "matrix.md")
                require((directory / name / "matrix.md").is_file(), "Markdown matrix is missing")
                step["counts"] = counts
                step["reports"] = {"json": f"{name}/matrix.json", "markdown": f"{name}/matrix.md"}
                step["status"] = {0: "PASS", 1: "FAIL", 2: "INCOMPLETE"}[report["exit_code"]]
                step["detail"] = "Complete local matrix reread and validated against the inventory"
                step["failed_cases"] = [
                    {key: c[key] for key in ("id", "status", "expected", "observed")}
                    for c in report["cases"] if c["status"] not in ("PASS", "NOT_RUN")
                ]
        except (OSError, ValueError, TypeError, OverflowError, RecursionError):
            step.update(status="FAIL", detail="Matrix report missing, stale, reused or inconsistent with source/inventory/exit")
        steps.append(step)
        snapshots.append(snapshot)
    return finish(directory, steps, snapshots, args.repeat, source)


if __name__ == "__main__":
    raise SystemExit(main())
