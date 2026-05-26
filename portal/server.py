#!/usr/bin/env python3
"""Thin compatibility wrapper for the AIM portal application."""

import argparse
import os
import sys
from pathlib import Path

import uvicorn

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from portal.app.main import create_app as _create_app


def create_app(config_path=None):
    # type: (str | None) -> object
    resolved = config_path or os.getenv("PORTAL_CONFIG_PATH") or str(Path(__file__).resolve().with_name("portal-config.json"))
    return _create_app(resolved)


def main():
    # type: () -> None
    parser = argparse.ArgumentParser(description="Run the AIM portal server")
    parser.add_argument("--config", default=str(Path(__file__).resolve().with_name("portal-config.json")))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8550)
    args = parser.parse_args()
    os.environ["PORTAL_CONFIG_PATH"] = args.config
    uvicorn.run(
        "server:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
