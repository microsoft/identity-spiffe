"""File-backed policy config storage."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from .base import PolicyConfigStore

logger = logging.getLogger("isp-portal.storage.file")


class FilePolicyConfigStore(PolicyConfigStore):
    """Atomic file-backed config store."""

    def __init__(self, path):
        # type: (str) -> None
        self.path = Path(path)

    def _read(self):
        # type: () -> List[Dict[str, Any]]
        if not self.path.exists():
            return []
        try:
            with self.path.open(encoding="utf-8") as handle:
                data = json.load(handle)
            if not isinstance(data, list):
                logger.warning("Policy config file is not a list: %s", self.path)
                return []
            return [item for item in data if isinstance(item, dict)]
        except (json.JSONDecodeError, OSError):
            logger.exception("Failed to read policy config file")
            corrupt = self.path.with_suffix(".corrupt")
            try:
                self.path.replace(corrupt)
            except OSError:
                pass
            return []

    def _write(self, configs):
        # type: (List[Dict[str, Any]]) -> None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(configs, handle, indent=2)
        tmp.replace(self.path)

    async def list_configs(self):
        # type: () -> List[Dict[str, Any]]
        return await asyncio.to_thread(self._read)

    async def write_configs(self, configs):
        # type: (List[Dict[str, Any]]) -> None
        await asyncio.to_thread(self._write, configs)

    async def healthcheck(self):
        # type: () -> Dict[str, Any]
        return {
            "status": "healthy",
            "backend": "file",
            "path": str(self.path),
        }
