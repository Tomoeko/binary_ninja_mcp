from __future__ import annotations

import base64
import importlib.util
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

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
    def __init__(self, architectures: list[str], platforms: list[str], view_types: list[str]):
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
        bn = FakeBinaryNinja(["aarch64"], ["mac-aarch64"], ["Raw", "Mapped", "Mach-O"])
        architectures, platforms, views = headless_host.validate_runtime(bn)
        self.assertEqual(architectures, ["aarch64"])
        self.assertEqual(platforms, ["mac-aarch64"])
        self.assertIn("Mach-O", views)

    def test_ready_file_is_exclusive_and_contains_exact_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            ready_file = Path(directory) / "ready.json"
            payload = {
                "protocol": 1,
                "event": "ready",
                "instance_id": "instance-a",
                "pid": 123,
                "host": "127.0.0.1",
                "port": 45678,
            }
            headless_host.publish_ready_file(str(ready_file), payload)
            self.assertEqual(json.loads(ready_file.read_text()), payload)
            with self.assertRaises(FileExistsError):
                headless_host.publish_ready_file(str(ready_file), payload)

    def test_parent_pipe_eof_requests_shutdown(self):
        stopping = threading.Event()
        read_descriptor, write_descriptor = os.pipe()
        os.close(write_descriptor)
        try:
            headless_host.stop_on_stdin_eof(stopping, read_descriptor)
            self.assertTrue(stopping.is_set())
        finally:
            os.close(read_descriptor)


class LauncherTests(unittest.TestCase):
    def test_host_environment_prepends_binary_ninja_python(self):
        with tempfile.TemporaryDirectory() as directory:
            python_path = Path(directory) / "Contents/Resources/python"
            (python_path / "binaryninja").mkdir(parents=True)
            env = launcher.host_environment(python_path)
            self.assertEqual(env["PYTHONPATH"].split(":")[0], str(python_path))
            self.assertEqual(env["BN_DISABLE_USER_PLUGINS"], "1")
            self.assertEqual(env["BN_DISABLE_REPOSITORY_PLUGINS"], "1")
            self.assertEqual(env["BN_MCP_HEADLESS"], "1")

    def test_parser_accepts_multiple_startup_binaries(self):
        args = launcher.build_parser().parse_args(["--binary", "/tmp/one", "--binary", "/tmp/two"])
        self.assertEqual(args.binary, ["/tmp/one", "/tmp/two"])

    def test_parser_defaults_to_os_assigned_port(self):
        args = launcher.build_parser().parse_args([])
        self.assertEqual(args.port, 0)

    def test_binary_ninja_user_state_is_isolated_per_launcher(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            destination = root / "isolated"
            source.mkdir()
            (source / "license.dat").write_text("license", encoding="utf-8")
            (source / "settings.json").write_text("{}", encoding="utf-8")
            (source / "channels").mkdir()
            (source / "channels/plugin_status.json").write_text(
                "shared-state",
                encoding="utf-8",
            )
            environment: dict[str, str] = {}

            launcher.prepare_isolated_user_directory(
                environment,
                destination,
                source=source,
            )

            self.assertEqual(environment["BN_USER_DIRECTORY"], str(destination))
            self.assertEqual(environment["BN_LICENSE"], "license")
            self.assertFalse((destination / "license.dat").exists())
            self.assertEqual(
                (destination / "settings.json").read_text(encoding="utf-8"),
                "{}",
            )
            self.assertFalse((destination / "channels").exists())

    def _write_ready_record(self, path: Path, **overrides):
        payload = {
            "protocol": 1,
            "event": "ready",
            "instance_id": "instance-a",
            "pid": 123,
            "host": "127.0.0.1",
            "port": 45678,
        }
        payload.update(overrides)
        path.write_text(json.dumps(payload), encoding="utf-8")

    def test_ready_record_binds_port_to_child_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            ready_file = Path(directory) / "ready.json"
            self._write_ready_record(ready_file)
            endpoint = launcher.read_ready_file(
                ready_file,
                expected_instance_id="instance-a",
                expected_pid=123,
                expected_host="127.0.0.1",
            )
            self.assertEqual(
                endpoint,
                launcher.HostEndpoint("127.0.0.1", 45678, "instance-a"),
            )

            for field, value, message in (
                ("instance_id", "foreign", "identity"),
                ("pid", 999, "PID"),
                ("host", "localhost", "host"),
                ("port", 0, "port"),
            ):
                with self.subTest(field=field):
                    self._write_ready_record(ready_file, **{field: value})
                    with self.assertRaisesRegex(RuntimeError, message):
                        launcher.read_ready_file(
                            ready_file,
                            expected_instance_id="instance-a",
                            expected_pid=123,
                            expected_host="127.0.0.1",
                        )

    def test_partial_ready_record_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            ready_file = Path(directory) / "ready.json"
            ready_file.write_text('{"protocol":', encoding="utf-8")
            self.assertIsNone(
                launcher.read_ready_file(
                    ready_file,
                    expected_instance_id="instance-a",
                    expected_pid=123,
                    expected_host="127.0.0.1",
                )
            )

    def test_dead_child_cannot_be_replaced_by_foreign_status_server(self):
        process = mock.Mock(pid=123)
        process.poll.return_value = 1
        with tempfile.TemporaryDirectory() as directory:
            ready_file = Path(directory) / "ready.json"
            with (
                mock.patch.object(launcher.DIRECT_HTTP_OPENER, "open") as open_url,
                self.assertRaisesRegex(RuntimeError, "exited during startup"),
            ):
                launcher.wait_for_host(
                    process,
                    ready_file,
                    "instance-a",
                    "127.0.0.1",
                    "secret",
                    0.1,
                )
            open_url.assert_not_called()

    def test_wait_for_host_verifies_http_instance_and_token(self):
        process = mock.Mock(pid=123)
        process.poll.return_value = None
        response = mock.MagicMock(status=200)
        response.__enter__.return_value = response
        target = "/tmp/着色器/šhader.bin"
        with tempfile.TemporaryDirectory() as directory:
            ready_file = Path(directory) / "ready.json"
            self._write_ready_record(ready_file)
            with (
                mock.patch.object(
                    launcher.DIRECT_HTTP_OPENER, "open", return_value=response
                ) as open_url,
                mock.patch.object(
                    launcher.json,
                    "load",
                    return_value={"instance_id": "instance-a", "loaded": True},
                ),
            ):
                endpoint = launcher.wait_for_host(
                    process,
                    ready_file,
                    "instance-a",
                    "127.0.0.1",
                    "secret",
                    0.1,
                    require_loaded=True,
                    target_binary=target,
                )
        self.assertEqual(endpoint.port, 45678)
        request = open_url.call_args.args[0]
        self.assertEqual(
            request.get_header("X-binary-ninja-mcp-token"),
            "secret",
        )
        self.assertEqual(
            request.get_header("X-binary-ninja-view-b64"),
            base64.urlsafe_b64encode(target.encode("utf-8")).decode("ascii"),
        )

    def test_stop_process_closes_private_stdin_for_graceful_shutdown(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.stdin = mock.Mock(closed=False)
        process.wait.return_value = 0

        launcher.stop_process(process)

        process.stdin.close.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=5)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()

    def test_launcher_starts_only_a_lazy_bridge_and_does_not_inherit_the_lease(self):
        bridge = mock.Mock(pid=456)
        bridge.wait.return_value = 0
        config = mock.Mock()
        lease = mock.Mock()
        with (
            mock.patch.object(launcher, "resolve_executable", return_value="/host/python"),
            mock.patch.object(launcher, "find_bridge_python", return_value="/bridge/python"),
            mock.patch.object(
                launcher.shared_host,
                "build_shared_host_config",
                return_value=config,
            ) as build_config,
            mock.patch.object(
                launcher.shared_host,
                "create_client_lease",
                return_value=lease,
            ),
            mock.patch.object(
                launcher.subprocess,
                "Popen",
                return_value=bridge,
            ) as popen,
            mock.patch.object(launcher, "stop_process"),
        ):
            result = launcher.main(
                [
                    "--python",
                    "/host/python",
                    "--bn-python-path",
                    "/bn/python",
                    "--bridge-python",
                    "/bridge/python",
                ]
        )
        self.assertEqual(result, 0)
        build_config.assert_called_once()
        config.to_environment.assert_called_once()
        popen.assert_called_once()
        bridge_call = popen.call_args
        self.assertTrue(bridge_call.kwargs["close_fds"])
        self.assertEqual(bridge_call.kwargs["env"]["BINJA_MCP_PARENT_PID"], str(os.getpid()))
        bridge.wait.assert_called_once_with()
        lease.close.assert_called_once_with()

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
