import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent


class AdapterTests(unittest.TestCase):
    def test_output_collision_never_starts_connected_stack(self):
        sys.path.insert(0, str(HERE))
        self.addCleanup(sys.path.remove, str(HERE))
        spec = importlib.util.spec_from_file_location("connected_adapter", HERE / "run.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        run_cases = Mock(return_value=[])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "existing.json"
            path.write_text("preserve")
            with patch.dict(sys.modules, {"journeys": SimpleNamespace(run_cases=run_cases)}):
                try:
                    code = module.main(["--output", str(path)])
                except FileExistsError:
                    code = 2
            self.assertEqual(code, 2)
            run_cases.assert_not_called()
            self.assertEqual(path.read_text(), "preserve")

    def test_inventory_requires_no_browser_go_or_cloud(self):
        path = HERE / "run.py"
        self.assertTrue(path.exists(), "Connected browser adapter missing")
        result = subprocess.run([sys.executable, "-S", str(path), "--list"],
                                capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0)
        cases = json.loads(result.stdout)
        self.assertEqual(len(cases), 15)
        self.assertEqual(len({c["id"] for c in cases}), 15)
        self.assertTrue(all(c["profiles"] == ["local"] and c["suite"] == "e2e" for c in cases))

    def test_bootstrap_cleans_actual_process_and_listener(self):
        path = HERE / "bootstrap.py"
        self.assertTrue(path.exists(), "Process-owning bootstrap missing")
        spec = importlib.util.spec_from_file_location("connected_bootstrap", path)
        bootstrap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bootstrap)
        import httpx
        with bootstrap.application("backend", {}) as target:
            with httpx.Client(trust_env=False, timeout=3) as client:
                response = client.get(target + "/health")
                self.assertEqual(response.status_code, 200)
        with httpx.Client(trust_env=False, timeout=0.5) as client:
            with self.assertRaises(httpx.RequestError):
                client.get(target + "/health")


if __name__ == "__main__":
    unittest.main()
