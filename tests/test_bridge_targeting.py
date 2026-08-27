from __future__ import annotations

import importlib.util
import json
import os
import threading
import unittest
from pathlib import Path
from unittest import mock

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
        self.assertNotIn("timeout", calls[0])


if __name__ == "__main__":
    unittest.main()
