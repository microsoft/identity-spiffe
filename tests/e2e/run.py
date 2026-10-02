"""Connected browser-to-backend adapter; no cloud operations or product changes."""
import argparse
import json
import os
from pathlib import Path
import sys

from evidence import inventory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runner import exit_code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
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
    output = args.output.absolute()
    try:
        if any(p.is_symlink() for p in (output, *output.parents)):
            raise ValueError("Symlink output rejected")
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except (OSError, ValueError):
        print("BLOCKED: output must be a new file in an existing non-symlink directory.", file=sys.stderr)
        return 2
    with os.fdopen(fd, "w", encoding="utf-8") as report:
        selected = [c for c in inventory() if args.profile in c["profiles"]]
        rows = []
        if selected:
            try:
                from journeys import run_cases
            except ImportError as exc:
                rows = [dict(c, status="BLOCKED", duration_seconds=0,
                             observed="Connected prerequisite import unavailable: " + str(exc.name)) for c in selected]
            else:
                rows = run_cases(selected)
        json.dump({"cases": rows}, report, indent=2, allow_nan=False)
        report.write("\n")
    return exit_code(rows)


if __name__ == "__main__":
    sys.exit(main())
