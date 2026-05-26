"""Blob-backed policy config storage."""

import asyncio
import io
import json
import logging
from typing import Any, Dict, List, Optional

from .base import PolicyConfigStore

logger = logging.getLogger("aim-portal.storage.blob")


class BlobPolicyConfigStore(PolicyConfigStore):
    """JSON blob-backed config store with optimistic concurrency."""

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
        credential, service_client, container_client, blob_client = self._build_clients()
        try:
            downloader = blob_client.download_blob()
            raw = downloader.readall()
            etag = downloader.properties.etag if downloader.properties else None
            if not raw:
                return {"configs": [], "etag": etag}
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, list):
                logger.warning("Policy blob is not a list: %s", self.blob_name)
                data = []
            return {"configs": [item for item in data if isinstance(item, dict)], "etag": etag}
        except Exception as exc:
            status_code = getattr(exc, "status_code", None)
            if status_code == 404:
                return {"configs": [], "etag": None}
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

    def _upload(self, configs, etag):
        # type: (List[Dict[str, Any]], Optional[str]) -> None
        credential, service_client, container_client, blob_client = self._build_clients()
        payload = json.dumps(configs, indent=2).encode("utf-8")
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

    async def list_configs(self):
        # type: () -> List[Dict[str, Any]]
        data = await asyncio.to_thread(self._download)
        return data["configs"]

    async def write_configs(self, configs):
        # type: (List[Dict[str, Any]]) -> None
        last_error = None
        for _ in range(3):
            snapshot = await asyncio.to_thread(self._download)
            try:
                await asyncio.to_thread(self._upload, configs, snapshot.get("etag"))
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
