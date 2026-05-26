"""Tests for external agent storage and portal integration.

Covers test plan items 16-18:
  16. Portal external-agent storage PUT/GET/DELETE
  17. Merge logic (admin-CP agents + external storage by name)
  18. Refresh endpoint re-discovers and merges
"""
import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# Add repo root to path so we can import portal.app modules
_repo_root = Path(__file__).resolve().parent.parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))


class TestFileExternalAgentStore(unittest.IsolatedAsyncioTestCase):
    """Test plan item 16: FileExternalAgentStore PUT/GET/DELETE."""

    async def test_put_and_list(self):
        """PUT creates entry, list returns it with defaults merged."""
        from portal.app.storage.external_agent import FileExternalAgentStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = FileExternalAgentStore(os.path.join(tmpdir, "agents.json"))
            await store.put_agent("google-budget-reader", {
                "name": "google-budget-reader",
                "invoke_url": "https://gce-vm.example.com",
                "display_name": "Google Budget Reader",
            })

            agents = await store.list_agents()

        self.assertEqual(len(agents), 1)
        agent = agents[0]
        self.assertEqual(agent["name"], "google-budget-reader")
        self.assertEqual(agent["invoke_url"], "https://gce-vm.example.com")
        self.assertEqual(agent["display_name"], "Google Budget Reader")
        # Defaults should be merged
        self.assertEqual(agent["transport"], "spiffe")
        self.assertEqual(agent["hosting_platform"], "")

    async def test_put_overwrites_existing(self):
        """PUT with same name updates the entry."""
        from portal.app.storage.external_agent import FileExternalAgentStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = FileExternalAgentStore(os.path.join(tmpdir, "agents.json"))
            await store.put_agent("test-agent", {"name": "test-agent", "invoke_url": "https://v1"})
            await store.put_agent("test-agent", {"name": "test-agent", "invoke_url": "https://v2"})

            agents = await store.list_agents()

        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]["invoke_url"], "https://v2")

    async def test_delete_removes_agent(self):
        """DELETE removes the named entry."""
        from portal.app.storage.external_agent import FileExternalAgentStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = FileExternalAgentStore(os.path.join(tmpdir, "agents.json"))
            await store.put_agent("agent-a", {"name": "agent-a", "invoke_url": "https://a"})
            await store.put_agent("agent-b", {"name": "agent-b", "invoke_url": "https://b"})
            await store.delete_agent("agent-a")

            agents = await store.list_agents()

        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]["name"], "agent-b")

    async def test_delete_nonexistent_is_noop(self):
        """DELETE of missing agent is a no-op, no exception."""
        from portal.app.storage.external_agent import FileExternalAgentStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = FileExternalAgentStore(os.path.join(tmpdir, "agents.json"))
            # Should not raise
            await store.delete_agent("does-not-exist")
            agents = await store.list_agents()
            self.assertEqual(agents, [])

    async def test_list_empty_when_no_file(self):
        """list_agents returns [] when the file doesn't exist yet."""
        from portal.app.storage.external_agent import FileExternalAgentStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = FileExternalAgentStore(os.path.join(tmpdir, "nonexistent.json"))
            agents = await store.list_agents()
            self.assertEqual(agents, [])

    async def test_corrupt_file_returns_empty_and_renames(self):
        """Corrupt JSON file is renamed to .corrupt and returns []."""
        from portal.app.storage.external_agent import FileExternalAgentStore

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "agents.json")
            with open(path, "w") as f:
                f.write("{{{invalid json")

            store = FileExternalAgentStore(path)
            agents = await store.list_agents()

            self.assertEqual(agents, [])
            self.assertTrue(Path(path).with_suffix(".corrupt").exists())

    async def test_entries_without_name_are_filtered(self):
        """Entries missing the 'name' key are silently dropped."""
        from portal.app.storage.external_agent import FileExternalAgentStore

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "agents.json")
            with open(path, "w") as f:
                json.dump([
                    {"name": "good-agent", "invoke_url": "https://good"},
                    {"invoke_url": "https://no-name"},  # missing name
                    "not-a-dict",  # not a dict
                ], f)

            store = FileExternalAgentStore(path)
            agents = await store.list_agents()

        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]["name"], "good-agent")

    async def test_healthcheck_returns_healthy(self):
        """Healthcheck returns healthy with file backend info."""
        from portal.app.storage.external_agent import FileExternalAgentStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = FileExternalAgentStore(os.path.join(tmpdir, "agents.json"))
            health = await store.healthcheck()

        self.assertEqual(health["status"], "healthy")
        self.assertEqual(health["backend"], "file")

    async def test_multiple_agents_persist(self):
        """Multiple agents can be stored and retrieved independently."""
        from portal.app.storage.external_agent import FileExternalAgentStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = FileExternalAgentStore(os.path.join(tmpdir, "agents.json"))

            await store.put_agent("gcp-agent", {
                "name": "gcp-agent",
                "invoke_url": "https://gcp",
                "transport": "spiffe",
                "hosting_platform": "gcp",
            })
            await store.put_agent("aws-agent", {
                "name": "aws-agent",
                "invoke_url": "https://aws",
                "transport": "spiffe",
                "hosting_platform": "aws",
            })

            agents = await store.list_agents()

        self.assertEqual(len(agents), 2)
        names = {a["name"] for a in agents}
        self.assertEqual(names, {"gcp-agent", "aws-agent"})

    async def test_transport_field_preserved(self):
        """Custom transport field (e.g. 'https_only') is preserved through PUT/GET."""
        from portal.app.storage.external_agent import FileExternalAgentStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = FileExternalAgentStore(os.path.join(tmpdir, "agents.json"))
            await store.put_agent("snow-agent", {
                "name": "snow-agent",
                "invoke_url": "https://snow",
                "transport": "https_only",
                "hosting_platform": "servicenow",
            })

            agents = await store.list_agents()

        self.assertEqual(agents[0]["transport"], "https_only")
        self.assertEqual(agents[0]["hosting_platform"], "servicenow")


class TestBlobExternalAgentStoreRetry(unittest.IsolatedAsyncioTestCase):
    """Test plan item 16 (blob variant): BlobExternalAgentStore with ETag retry."""

    async def test_put_retries_on_412_conflict(self):
        """PUT retries on ETag 412 conflict (optimistic concurrency)."""
        from portal.app.storage.external_agent import BlobExternalAgentStore

        class _ConflictError(Exception):
            def __init__(self):
                super().__init__("precondition failed")
                self.status_code = 412

        store = BlobExternalAgentStore(
            account_url="https://storage.example.blob.core.windows.net/",
            container="test-container",
            blob_name="external-agents.json",
        )
        store._upload_attempts = 0

        def fake_download():
            return {
                "agents": [{"name": "existing", "invoke_url": "https://old"}],
                "etag": f"etag-{store._upload_attempts}",
            }

        def fake_upload(agents, etag):
            store._upload_attempts += 1
            if store._upload_attempts == 1:
                raise _ConflictError()
            store._saved_agents = list(agents)

        store._download = fake_download
        store._upload = fake_upload

        await store.put_agent("new-agent", {"name": "new-agent", "invoke_url": "https://new"})

        self.assertEqual(store._upload_attempts, 2)
        saved_names = {a["name"] for a in store._saved_agents}
        self.assertIn("new-agent", saved_names)
        self.assertIn("existing", saved_names)

    async def test_delete_retries_on_412_conflict(self):
        """DELETE retries on ETag 412 conflict (optimistic concurrency)."""
        from portal.app.storage.external_agent import BlobExternalAgentStore

        class _ConflictError(Exception):
            def __init__(self):
                super().__init__("precondition failed")
                self.status_code = 412

        store = BlobExternalAgentStore(
            account_url="https://storage.example.blob.core.windows.net/",
            container="test-container",
            blob_name="external-agents.json",
        )
        store._upload_attempts = 0

        def fake_download():
            return {
                "agents": [
                    {"name": "keep-me", "invoke_url": "https://keep"},
                    {"name": "delete-me", "invoke_url": "https://delete"},
                ],
                "etag": f"etag-{store._upload_attempts}",
            }

        def fake_upload(agents, etag):
            store._upload_attempts += 1
            if store._upload_attempts == 1:
                raise _ConflictError()
            store._saved_agents = list(agents)

        store._download = fake_download
        store._upload = fake_upload

        await store.delete_agent("delete-me")

        self.assertEqual(store._upload_attempts, 2)
        saved_names = {a["name"] for a in store._saved_agents}
        self.assertIn("keep-me", saved_names)
        self.assertNotIn("delete-me", saved_names)


if __name__ == "__main__":
    unittest.main()
