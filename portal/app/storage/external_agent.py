"""External agent metadata storage backends."""

import asyncio
import io
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import ExternalAgentStore

logger = logging.getLogger("isp-portal.storage.external_agent")

# Required string fields with default values
_AGENT_DEFAULTS = {
    "invoke_url": "",
    "display_name": "",
    "transport": "spiffe",
    "hosting_platform": "",
}


def _merge_defaults(entry):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    result = dict(_AGENT_DEFAULTS)
    result.update(entry)
    return result


class BlobExternalAgentStore(ExternalAgentStore):
    """Azure Blob Storage-backed external agent store with optimistic concurrency."""

    def __init__(self, account_url, container, blob_name, managed_identity_client_id=""):
        # type: (str, str, str, str) -> None
        self.account_url = account_url.rstrip("/")
        self.container = container
        self.blob_name = blob_name
        self.managed_identity_client_id = managed_identity_client_id

    def _build_clients(self):
        # type: () -> tuple
        from azure.identity import ManagedIdentityCredential
        from azure.storage.blob import BlobServiceClient

        credential = ManagedIdentityCredential(
            client_id=self.managed_identity_client_id or None,
        )
        service_client = BlobServiceClient(account_url=self.account_url, credential=credential)
        container_client = service_client.get_container_client(self.container)
        blob_client = container_client.get_blob_client(self.blob_name)
        return credential, service_client, container_client, blob_client

    def _download(self):
        # type: () -> Dict[str, Any]
        """Download blob and return {"agents": [...], "etag": ...}."""
        credential, service_client, container_client, blob_client = self._build_clients()
        try:
            downloader = blob_client.download_blob()
            raw = downloader.readall()
            etag = downloader.properties.etag if downloader.properties else None
            if not raw:
                return {"agents": [], "etag": etag}
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, list):
                logger.warning("External agent blob is not a list: %s", self.blob_name)
                data = []
            return {
                "agents": [_merge_defaults(e) for e in data if isinstance(e, dict) and "name" in e],
                "etag": etag,
            }
        except Exception as exc:
            status_code = getattr(exc, "status_code", None)
            if status_code == 404:
                return {"agents": [], "etag": None}
            raise
        finally:
            try:
                service_client.close()
            except Exception:
                pass
            try:
                credential.close()
            except Exception:
                pass

    def _upload(self, agents, etag):
        # type: (List[Dict[str, Any]], Optional[str]) -> None
        credential, service_client, container_client, blob_client = self._build_clients()
        payload = json.dumps(agents, indent=2).encode("utf-8")
        try:
            kwargs = {"overwrite": True}
            if etag:
                from azure.core.match_conditions import MatchConditions
                kwargs["etag"] = etag
                kwargs["match_condition"] = MatchConditions.IfNotModified
            blob_client.upload_blob(io.BytesIO(payload), **kwargs)
        finally:
            try:
                service_client.close()
            except Exception:
                pass
            try:
                credential.close()
            except Exception:
                pass

    async def list_agents(self):
        # type: () -> List[Dict[str, Any]]
        data = await asyncio.to_thread(self._download)
        return data["agents"]

    async def put_agent(self, name, config):
        # type: (str, Dict[str, Any]) -> None
        last_error = None
        for _ in range(3):
            snapshot = await asyncio.to_thread(self._download)
            agents = {e["name"]: e for e in snapshot["agents"]}
            entry = _merge_defaults(config)
            entry["name"] = name
            agents[name] = entry
            try:
                await asyncio.to_thread(self._upload, list(agents.values()), snapshot.get("etag"))
                return
            except Exception as exc:
                last_error = exc
                status_code = getattr(exc, "status_code", None)
                if status_code != 412:
                    raise
        if last_error:
            raise last_error

    async def delete_agent(self, name):
        # type: (str) -> None
        last_error = None
        for _ in range(3):
            snapshot = await asyncio.to_thread(self._download)
            agents = {e["name"]: e for e in snapshot["agents"]}
            if name not in agents:
                return  # already gone — no-op
            del agents[name]
            try:
                await asyncio.to_thread(self._upload, list(agents.values()), snapshot.get("etag"))
                return
            except Exception as exc:
                last_error = exc
                status_code = getattr(exc, "status_code", None)
                if status_code != 412:
                    raise
        if last_error:
            raise last_error

    async def healthcheck(self):
        # type: () -> Dict[str, Any]
        def _check():
            # type: () -> Dict[str, Any]
            credential, service_client, container_client, blob_client = self._build_clients()
            try:
                container_client.get_container_properties()
                return {
                    "status": "healthy",
                    "backend": "blob",
                    "account_url": self.account_url,
                    "container": self.container,
                    "blob": self.blob_name,
                }
            except Exception as exc:
                return {
                    "status": "unhealthy",
                    "backend": "blob",
                    "error": str(exc),
                }
            finally:
                try:
                    service_client.close()
                except Exception:
                    pass
                try:
                    credential.close()
                except Exception:
                    pass

        return await asyncio.to_thread(_check)


class FileExternalAgentStore(ExternalAgentStore):
    """Atomic file-backed external agent store (local / dev)."""

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
                logger.warning("External agent file is not a list: %s", self.path)
                return []
            return [_merge_defaults(e) for e in data if isinstance(e, dict) and "name" in e]
        except (json.JSONDecodeError, OSError):
            logger.exception("Failed to read external agent file")
            corrupt = self.path.with_suffix(".corrupt")
            try:
                self.path.replace(corrupt)
            except OSError:
                pass
            return []

    def _write(self, agents):
        # type: (List[Dict[str, Any]]) -> None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(agents, handle, indent=2)
        tmp.replace(self.path)

    async def list_agents(self):
        # type: () -> List[Dict[str, Any]]
        return await asyncio.to_thread(self._read)

    async def put_agent(self, name, config):
        # type: (str, Dict[str, Any]) -> None
        def _do():
            # type: () -> None
            agents = {e["name"]: e for e in self._read()}
            entry = _merge_defaults(config)
            entry["name"] = name
            agents[name] = entry
            self._write(list(agents.values()))

        await asyncio.to_thread(_do)

    async def delete_agent(self, name):
        # type: (str) -> None
        def _do():
            # type: () -> None
            agents = {e["name"]: e for e in self._read()}
            if name not in agents:
                return
            del agents[name]
            self._write(list(agents.values()))

        await asyncio.to_thread(_do)

    async def healthcheck(self):
        # type: () -> Dict[str, Any]
        return {
            "status": "healthy",
            "backend": "file",
            "path": str(self.path),
        }
