"""Parent-runner adapter. --list works with Python -S and no dependencies."""
import argparse
import json
import os
from pathlib import Path
import sys

from browser_catalog import inventory
from browser_guards import case_result, validate_debug_environment, write_private_json


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--profile", choices=("local", "live"), default="local")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.list:
        print(json.dumps(inventory()))
        return 0
    if args.output is None:
        parser.error("--output is required")
    selected = [c for c in inventory() if args.profile in c["profiles"]]
    config = {}
    code = None
    if args.config:
        try:
            config = json.loads(args.config.read_text(encoding="utf-8"))
            if not isinstance(config, dict) or not isinstance(config.get("browser", {}), dict):
                code = "config_missing"
                config = {}
        except (OSError, ValueError):
            code = "config_missing"
    if args.profile == "live" and not config.get("browser"):
        code = "config_missing"
    try:
        validate_debug_environment(os.environ)
    except ValueError:
        code = "unsafe_debug"
    if code:
        rows = [case_result(c, "BLOCKED", code, 0) for c in selected]
    else:
        try:
            from browser_engine import run_cases
        except ImportError:
            rows = [case_result(c, "BLOCKED", "dependency_missing", 0) for c in selected]
        else:
            try:
                rows = run_cases(selected, args.profile, config.get("browser", {}))
            except Exception:
                # Top-level reporting boundary: failed startup/teardown is never a pass.
                rows = [case_result(c, "FAIL", "unexpected_error", 0) for c in selected]
    write_private_json(args.output, {"cases": rows})
    return 1 if any(r["status"] == "FAIL" for r in rows) else (
        2 if any(r["status"] in {"BLOCKED", "SKIPPED"} for r in rows) else 0)


if __name__ == "__main__":
    sys.exit(main())
