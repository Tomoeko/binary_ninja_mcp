from __future__ import annotations

import importlib.util
import tempfile
import unittest
from unittest import mock
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


launcher = load_module("run_headless_mcp", REPO_ROOT / "scripts/run_headless_mcp.py")
headless_host = load_module("headless_host", REPO_ROOT / "bridge/headless_host.py")


class Named:
    def __init__(self, name: str):
        self.name = name


class FakeBinaryNinja:
    def __init__(
        self, architectures: list[str], platforms: list[str], view_types: list[str]
    ):
        self.Architecture = [Named(name) for name in architectures]
        self.Platform = [Named(name) for name in platforms]
        self.BinaryViewType = [Named(name) for name in view_types]
        self.initialized = False

    def _init_plugins(self):
        self.initialized = True


class HeadlessHostTests(unittest.TestCase):
    def test_runtime_requires_native_analysis_plugins(self):
        bn = FakeBinaryNinja([], [], ["Raw", "Mapped"])
        with self.assertRaisesRegex(RuntimeError, "native analysis plugins"):
            headless_host.validate_runtime(bn)
        self.assertTrue(bn.initialized)

    def test_runtime_accepts_architecture_and_format_view(self):
        bn = FakeBinaryNinja(
            ["aarch64"], ["mac-aarch64"], ["Raw", "Mapped", "Mach-O"]
        )
        architectures, platforms, views = headless_host.validate_runtime(bn)
        self.assertEqual(architectures, ["aarch64"])
        self.assertEqual(platforms, ["mac-aarch64"])
        self.assertIn("Mach-O", views)


class LauncherTests(unittest.TestCase):
    def test_host_environment_prepends_binary_ninja_python(self):
        with tempfile.TemporaryDirectory() as directory:
            python_path = Path(directory) / "Contents/Resources/python"
            (python_path / "binaryninja").mkdir(parents=True)
            env = launcher.host_environment(python_path)
            self.assertEqual(env["PYTHONPATH"].split(":")[0], str(python_path))
            self.assertEqual(env["BN_DISABLE_USER_PLUGINS"], "1")
            self.assertEqual(env["BN_MCP_HEADLESS"], "1")

    def test_parser_accepts_multiple_startup_binaries(self):
        args = launcher.build_parser().parse_args(
            ["--binary", "/tmp/one", "--binary", "/tmp/two"]
        )
        self.assertEqual(args.binary, ["/tmp/one", "/tmp/two"])

    def test_supervisor_stops_bridge_when_host_exits(self):
        host = mock.Mock()
        bridge = mock.Mock()
        host.poll.return_value = -9
        bridge.poll.return_value = None
        with mock.patch.object(launcher, "stop_process") as stop:
            self.assertEqual(launcher.supervise_processes(host, bridge), -9)
            stop.assert_called_once_with(bridge)

    def test_supervisor_returns_bridge_status(self):
        host = mock.Mock()
        bridge = mock.Mock()
        host.poll.return_value = None
        bridge.poll.return_value = 0
        self.assertEqual(launcher.supervise_processes(host, bridge), 0)


if __name__ == "__main__":
    unittest.main()
