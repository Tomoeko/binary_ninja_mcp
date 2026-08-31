from __future__ import annotations

import importlib.util
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import requests

REPO_ROOT = Path(__file__).resolve().parents[1]


class FakeResponse:
    def __init__(self, payload: dict[str, object]):
        self._payload = payload
        self.ok = True
        self.status_code = 200
        self.encoding = "utf-8"
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


@unittest.skipUnless(importlib.util.find_spec("mcp"), "bridge MCP dependency absent")
class BridgeTargetingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.environment = mock.patch.dict(
            os.environ,
            {
                "BINJA_MCP_HOST": "127.0.0.1",
                "BINJA_MCP_PORT": "45678",
                "BINJA_MCP_AUTH_TOKEN": "test-secret",
            },
        )
        cls.environment.start()
        path = REPO_ROOT / "bridge" / "binja_mcp_bridge.py"
        spec = importlib.util.spec_from_file_location("bridge_targeting_test", path)
        assert spec and spec.loader
        cls.bridge = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.bridge)

    @classmethod
    def tearDownClass(cls):
        cls.environment.stop()

    def test_analysis_tool_schema_exposes_binary_but_session_tools_do_not(self):
        self.assertFalse(self.bridge._http.trust_env)
        manager = self.bridge.mcp._tool_manager
        analysis = manager.get_tool("decompile_function").parameters["properties"]
        self.assertIn("binary", analysis)
        for name in (
            "close_binary",
            "convert_number",
            "list_binaries",
            "list_platforms",
            "open_binary",
            "select_binary",
        ):
            properties = manager.get_tool(name).parameters.get("properties", {})
            self.assertNotIn("binary", properties)

    def test_target_and_auth_apply_to_every_request_in_one_tool_call(self):
        calls: list[tuple[str, dict]] = []

        def get(url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith("/status"):
                return FakeResponse({"filename": "/tmp/a.bin"})
            return FakeResponse({"decompiled": "int target(void) { return 1; }"})

        with mock.patch.object(self.bridge._http, "get", side_effect=get):
            result = self.bridge.decompile_function(
                "operator +",
                binary="/tmp/a.bin",
            )

        self.assertIn("File: /tmp/a.bin", result)
        self.assertEqual(len(calls), 2)
        for url, kwargs in calls:
            self.assertNotIn("?", url)
            self.assertEqual(
                kwargs["headers"],
                {
                    "X-Binary-Ninja-MCP-Token": "test-secret",
                    "X-Binary-Ninja-View-B64": "L3RtcC9hLmJpbg==",
                },
            )
        self.assertEqual(calls[1][1]["params"], {"name": "operator +"})
        self.assertNotIn("X-Binary-Ninja-View-B64", self.bridge._request_headers())

    def test_concurrent_tool_contexts_do_not_leak_targets(self):
        barrier = threading.Barrier(2)
        captured: list[str] = []
        capture_lock = threading.Lock()

        def get(_url, **kwargs):
            barrier.wait(timeout=2)
            encoded = kwargs["headers"]["X-Binary-Ninja-View-B64"]
            target = self.bridge._base64.urlsafe_b64decode(encoded).decode("utf-8")
            with capture_lock:
                captured.append(target)
            return FakeResponse({"filename": target, "loaded": True})

        failures: list[BaseException] = []

        def invoke(target: str):
            try:
                self.bridge.get_binary_status(binary=target)
            except BaseException as exc:
                failures.append(exc)

        with mock.patch.object(self.bridge._http, "get", side_effect=get):
            threads = [
                threading.Thread(target=invoke, args=("/tmp/a.bin",)),
                threading.Thread(target=invoke, args=("/tmp/b.bin",)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=3)

        self.assertFalse(failures)
        self.assertCountEqual(captured, ["/tmp/a.bin", "/tmp/b.bin"])

    def test_unicode_target_round_trips_through_the_encoded_header(self):
        target = "/tmp/着色器/šhader.bin"
        captured: list[str] = []

        def get(_url, **kwargs):
            encoded = kwargs["headers"]["X-Binary-Ninja-View-B64"]
            decoded = self.bridge._base64.urlsafe_b64decode(encoded).decode("utf-8")
            captured.append(decoded)
            return FakeResponse({"filename": decoded, "loaded": True})

        with mock.patch.object(self.bridge._http, "get", side_effect=get):
            result = self.bridge.get_binary_status(binary=target)

        self.assertEqual(captured, [target])
        self.assertEqual(json.loads(result)["filename"], target)

    def test_open_binary_returns_a_namespaced_stable_selector(self):
        response = FakeResponse(
            {
                "success": True,
                "message": "Binary opened: /tmp/a.bin; background analysis started",
                "filename": "/tmp/a.bin",
                "view_id": "2",
                "view_selector": "view:2",
            }
        )
        with mock.patch.object(
            self.bridge._http,
            "post",
            return_value=response,
        ):
            result = self.bridge.open_binary("/tmp/a.bin")

        self.assertIn("Stable selector: view:2", result)
        self.assertNotIn("Stable selector: 2\n", result)

    def test_mutations_wait_for_an_authoritative_server_response(self):
        calls: list[dict] = []

        def get(_url, **kwargs):
            calls.append(kwargs)
            return FakeResponse(
                {
                    "status": "ok",
                    "address": "0x1000",
                    "applied_type": "int target(void)",
                }
            )

        with mock.patch.object(self.bridge._http, "get", side_effect=get):
            result = self.bridge.set_function_prototype(
                "target",
                "int target(void)",
                binary="view:1",
            )

        self.assertIn("Applied prototype", result)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["timeout"], self.bridge._DEFAULT_HTTP_TIMEOUT)

    def test_default_transport_has_short_connect_and_long_finite_read_budget(self):
        response = FakeResponse({"filename": "/tmp/a.bin", "loaded": True})
        with (
            mock.patch.object(self.bridge._http, "get", return_value=response) as get,
            mock.patch.object(self.bridge._http, "post", return_value=response) as post,
            mock.patch.object(self.bridge._http, "delete", return_value=response) as delete,
        ):
            self.bridge.safe_get("status")
            self.bridge.get_json("status")
            self.bridge.get_text("status")
            self.bridge.safe_post("comment", {"address": "0x1000", "comment": "ok"})
            self.bridge.safe_delete("comment", {"address": "0x1000"})

        calls = [*get.call_args_list, *post.call_args_list, *delete.call_args_list]
        self.assertEqual(len(calls), 5)
        for call in calls:
            self.assertEqual(call.kwargs["timeout"], self.bridge._DEFAULT_HTTP_TIMEOUT)
        self.assertEqual(self.bridge._HTTP_CONNECT_TIMEOUT_SEC, 5.0)
        self.assertEqual(self.bridge._HTTP_READ_TIMEOUT_SEC, 1740.0)

    def test_default_request_survives_a_serialized_host_queue(self):
        operation_lock = threading.Lock()
        slow_entered = threading.Event()
        release_slow = threading.Event()
        abandoned_entered = threading.Event()
        queued_entered = threading.Event()

        class QueueingHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                if self.path.startswith("/abandoned"):
                    abandoned_entered.set()
                if self.path.startswith("/queued"):
                    queued_entered.set()
                with operation_lock:
                    if self.path.startswith("/slow"):
                        slow_entered.set()
                        release_slow.wait(timeout=10)
                    payload = json.dumps({"path": self.path}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    try:
                        self.wfile.write(payload)
                    except OSError:
                        pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), QueueingHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        previous_url = self.bridge.binja_server_url
        self.bridge.binja_server_url = f"http://127.0.0.1:{server.server_address[1]}"
        slow_result: list[object] = []
        slow_thread = threading.Thread(
            target=lambda: slow_result.append(self.bridge.get_json("slow"))
        )
        queued_result: list[object] = []
        queued_thread = threading.Thread(
            target=lambda: queued_result.append(self.bridge.get_json("queued"))
        )
        try:
            slow_thread.start()
            self.assertTrue(slow_entered.wait(timeout=2))

            # Reproduce the old failure with a compressed timeout: a scalar
            # request abandons a healthy operation solely because it is queued
            # behind the host lock.
            control = requests.Session()
            control.trust_env = False
            with self.assertRaises(requests.exceptions.ReadTimeout):
                control.get(
                    f"{self.bridge.binja_server_url}/abandoned",
                    timeout=(0.05, 0.05),
                )
            control.close()
            self.assertTrue(abandoned_entered.wait(timeout=2))

            queued_thread.start()
            self.assertTrue(queued_entered.wait(timeout=2))
            self.assertTrue(slow_thread.is_alive())
            release_slow.set()

            slow_thread.join(timeout=2)
            queued_thread.join(timeout=2)
            self.assertFalse(slow_thread.is_alive())
            self.assertFalse(queued_thread.is_alive())
            self.assertEqual(slow_result, [{"path": "/slow"}])
            self.assertEqual(queued_result, [{"path": "/queued"}])
        finally:
            release_slow.set()
            slow_thread.join(timeout=2)
            queued_thread.join(timeout=2)
            self.bridge.binja_server_url = previous_url
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)

    def test_http_sessions_are_isolated_per_worker_thread(self):
        created: list[object] = []
        create_lock = threading.Lock()

        class Session:
            def __init__(self):
                self.trust_env = True

        def factory():
            session = Session()
            with create_lock:
                created.append(session)
            return session

        client = self.bridge._ThreadLocalHttpClient(factory)
        barrier = threading.Barrier(2)
        observed: list[object] = []

        def worker():
            session = client._session()
            barrier.wait(timeout=2)
            observed.append(session)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=3)

        self.assertEqual(len(created), 2)
        self.assertEqual(len({id(session) for session in observed}), 2)
        self.assertTrue(all(session.trust_env is False for session in created))

    def _host_record(self, instance: str, port: int):
        return SimpleNamespace(
            endpoint=SimpleNamespace(
                host="127.0.0.1",
                port=port,
                instance_id=instance,
            ),
            auth_token=f"token-{instance}",
        )

    def _start_http_server(self, handler_class):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def test_declared_partial_read_retries_against_recovered_host(self):
        truncated_hits: list[str] = []
        recovered_hits: list[str] = []

        class TruncatedHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                truncated_hits.append(self.path)
                partial = b'{"loaded":'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(partial) + 20))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(partial)
                self.wfile.flush()
                self.close_connection = True

        class RecoveredHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                recovered_hits.append(self.path)
                body = json.dumps({"loaded": False, "instance_id": "new"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

        truncated_server = self._start_http_server(TruncatedHandler)
        recovered_server = self._start_http_server(RecoveredHandler)
        old = self._host_record("old", truncated_server.server_address[1])
        new = self._host_record("new", recovered_server.server_address[1])
        runtime = mock.Mock()
        runtime.ensure_host.return_value = old
        runtime.recover_after_connection_loss.return_value = new

        with mock.patch.object(self.bridge, "_shared_host_runtime", runtime):
            result = self.bridge.get_json("status")

        self.assertEqual(result, {"loaded": False, "instance_id": "new"})
        self.assertEqual(truncated_hits, ["/status"])
        self.assertEqual(recovered_hits, ["/status"])
        runtime.recover_after_connection_loss.assert_called_once_with("old")

    def test_declared_partial_mutation_is_unknown_and_never_replayed(self):
        truncated_hits: list[str] = []
        replacement_hits: list[str] = []

        class TruncatedHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                truncated_hits.append(self.path)
                partial = b'{"status":'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(partial) + 20))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(partial)
                self.wfile.flush()
                self.close_connection = True

        class ReplacementHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                replacement_hits.append(self.path)
                body = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        truncated_server = self._start_http_server(TruncatedHandler)
        replacement_server = self._start_http_server(ReplacementHandler)
        old = self._host_record("old", truncated_server.server_address[1])
        new = self._host_record("new", replacement_server.server_address[1])
        runtime = mock.Mock()
        runtime.ensure_host.return_value = old
        runtime.recover_after_connection_loss.return_value = new

        with mock.patch.object(self.bridge, "_shared_host_runtime", runtime):
            result = self.bridge.get_json("patch", {"address": "0x1000"})

        self.assertIn("outcome is unknown", result["error"])
        self.assertEqual(len(truncated_hits), 1)
        self.assertIn("/patch", truncated_hits[0])
        self.assertEqual(replacement_hits, [])
        runtime.recover_after_connection_loss.assert_called_once_with("old")

    def test_read_only_reset_retries_without_replacing_a_healthy_generation(self):
        old = self._host_record("old", 41001)
        runtime = mock.Mock()
        runtime.ensure_host.return_value = old
        runtime.recover_after_connection_loss.return_value = old
        with (
            mock.patch.object(self.bridge, "_shared_host_runtime", runtime),
            mock.patch.object(
                self.bridge._http,
                "get",
                side_effect=[
                    requests.exceptions.ConnectionError("reset"),
                    FakeResponse({"loaded": False}),
                ],
            ) as get,
        ):
            result = self.bridge.get_json("status")
        self.assertEqual(result, {"loaded": False})
        self.assertEqual(get.call_count, 2)
        runtime.recover_after_connection_loss.assert_called_once_with("old")
        self.assertTrue(all("41001" in call.args[0] for call in get.call_args_list))

    def test_mutation_reset_recovers_transport_but_never_replays(self):
        old = self._host_record("old", 41001)
        runtime = mock.Mock()
        runtime.ensure_host.return_value = old
        runtime.recover_after_connection_loss.return_value = old
        with (
            mock.patch.object(self.bridge, "_shared_host_runtime", runtime),
            mock.patch.object(
                self.bridge._http,
                "get",
                side_effect=requests.exceptions.ConnectionError("reset"),
            ) as get,
        ):
            result = self.bridge.get_json("patch", {"address": "0x1000"})
        self.assertIn("outcome is unknown", result["error"])
        self.assertEqual(get.call_count, 1)
        runtime.recover_after_connection_loss.assert_called_once_with("old")

    def test_mutation_read_timeout_is_unknown_and_does_not_replace_host(self):
        old = self._host_record("old", 41001)
        runtime = mock.Mock()
        runtime.ensure_host.return_value = old
        with (
            mock.patch.object(self.bridge, "_shared_host_runtime", runtime),
            mock.patch.object(
                self.bridge._http,
                "get",
                side_effect=requests.exceptions.ReadTimeout("slow"),
            ) as get,
        ):
            result = self.bridge.get_json("patch", {"address": "0x1000"})
        self.assertIn("outcome is unknown", result["error"])
        self.assertEqual(get.call_count, 1)
        runtime.recover_after_connection_loss.assert_not_called()


if __name__ == "__main__":
    unittest.main()
