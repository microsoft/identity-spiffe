import tempfile
import unittest
from pathlib import Path

from portal.app.storage.blob import BlobPolicyConfigStore
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
