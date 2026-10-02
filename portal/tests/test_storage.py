import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from azure.core import MatchConditions
from azure.core.pipeline.transport import HttpResponse, HttpTransport
from azure.storage.blob import BlobClient
from portal.app.storage.blob import BlobPolicyConfigStore
from portal.app.storage.external_agent import BlobExternalAgentStore
from portal.app.storage.file import FilePolicyConfigStore


class _ConflictError(Exception):
    def __init__(self):
        super().__init__("precondition failed")
        self.status_code = 412


class _FakeBlobPolicyConfigStore(BlobPolicyConfigStore):
    def __init__(self):
        super().__init__(
            account_url="https://storage.example.blob.core.windows.net/",
            container="portal-policy-configs",
            blob_name="policy-configs.json",
        )
        self.upload_attempts = 0
        self.saved_configs = None

    def _download(self):
        return {"configs": [], "etag": "etag-{0}".format(self.upload_attempts)}

    def _upload(self, configs, etag):
        self.upload_attempts += 1
        if self.upload_attempts == 1:
            raise _ConflictError()
        self.saved_configs = list(configs)


class _UploadResponse(HttpResponse):
    def __init__(self, request):
        super().__init__(request, None)
        self.status_code = 201
        self.reason = "Created"
        self.headers = {"etag": '"saved"', "last-modified": "Thu, 01 Oct 2026 20:00:00 GMT"}
        self.content_type = "application/xml"

    def body(self):
        return b""


class _UploadTransport(HttpTransport):
    def __init__(self):
        self.requests = []

    def open(self):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def send(self, request, **_kwargs):
        self.requests.append(request)
        return _UploadResponse(request)


class TestPolicyStores(unittest.IsolatedAsyncioTestCase):
    async def test_file_policy_store_persists_across_instances(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy-configs.json"
            configs = [{"name": "baseline", "yaml": "version: 1", "created_at": "now", "updated_at": "now"}]
            writer = FilePolicyConfigStore(str(path))
            await writer.write_configs(configs)

            reader = FilePolicyConfigStore(str(path))
            loaded = await reader.list_configs()

        self.assertEqual(loaded, configs)

    async def test_blob_policy_store_retries_on_conflict(self):
        store = _FakeBlobPolicyConfigStore()
        configs = [{"name": "baseline", "yaml": "version: 1", "created_at": "now", "updated_at": "now"}]

        await store.write_configs(configs)

        self.assertEqual(store.upload_attempts, 2)
        self.assertEqual(store.saved_configs, configs)

    async def test_settings_write_uses_real_sdk_etag_condition(self):
        transport = _UploadTransport()
        blob = BlobClient(
            account_url="https://storage.example.blob.core.windows.net",
            container_name="portal-runtime-settings", blob_name="settings.json",
            transport=transport,
        )
        store = BlobPolicyConfigStore(
            "https://storage.example.blob.core.windows.net",
            "portal-runtime-settings", "settings.json", strict=True,
        )
        configs = [{"entra_signal_enabled": False, "risk_enforcement_enabled": False}]
        with patch.object(store, "_download", return_value={"configs": [], "etag": '"existing"'}), \
                patch.object(store, "_build_clients", return_value=(Mock(), Mock(), Mock(), blob)):
            await store.write_configs(configs)
        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(transport.requests[0].headers["If-Match"], '"existing"')
        self.assertEqual(transport.requests[0].method, "PUT")
        self.assertEqual(MatchConditions.IfNotModified.name, "IfNotModified")

    async def test_external_agent_write_uses_real_sdk_etag_condition(self):
        transport = _UploadTransport()
        blob = BlobClient(
            account_url="https://storage.example.blob.core.windows.net",
            container_name="portal-external-agents", blob_name="agents.json",
            transport=transport,
        )
        store = BlobExternalAgentStore(
            "https://storage.example.blob.core.windows.net",
            "portal-external-agents", "agents.json",
        )
        with patch.object(store, "_download", return_value={"agents": [], "etag": '"existing"'}), \
                patch.object(store, "_build_clients", return_value=(Mock(), Mock(), Mock(), blob)):
            await store.put_agent("fixture", {"invoke_url": "https://fixture.example"})
        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(transport.requests[0].headers["If-Match"], '"existing"')
