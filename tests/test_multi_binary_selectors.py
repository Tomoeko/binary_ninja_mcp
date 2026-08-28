from __future__ import annotations

import base64
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PACKAGE = "binary_ninja_mcp_selector_fixture"


class _BinaryNinjaType:
    pass


class _FakeBinaryNinja(types.ModuleType):
    def __getattr__(self, _name: str):
        return _BinaryNinjaType


class _BinaryNinjaConfig:
    pass


def _package(name: str, path: Path) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__path__ = [str(path)]
    return module


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_selector_modules():
    saved_modules = {
        name: sys.modules.get(name)
        for name in (
            "binaryninja",
            "binaryninja.enums",
            "binaryninja.settings",
        )
    }

    binaryninja = _FakeBinaryNinja("binaryninja")
    binaryninja.log_info = lambda *_args, **_kwargs: None
    binaryninja.log_warn = lambda *_args, **_kwargs: None
    binaryninja.log_error = lambda *_args, **_kwargs: None
    binaryninja.Platform = []
    enums = types.ModuleType("binaryninja.enums")
    enums.AnalysisState = _BinaryNinjaType
    enums.StructureVariant = _BinaryNinjaType
    enums.TypeClass = _BinaryNinjaType
    settings = types.ModuleType("binaryninja.settings")
    settings.Settings = _BinaryNinjaType

    package_root = _package(FIXTURE_PACKAGE, REPO_ROOT / "plugin")
    api_package = _package(f"{FIXTURE_PACKAGE}.api", REPO_ROOT / "plugin/api")
    core_package = _package(f"{FIXTURE_PACKAGE}.core", REPO_ROOT / "plugin/core")
    server_package = _package(f"{FIXTURE_PACKAGE}.server", REPO_ROOT / "plugin/server")
    utils_package = _package(f"{FIXTURE_PACKAGE}.utils", REPO_ROOT / "plugin/utils")

    config = types.ModuleType(f"{FIXTURE_PACKAGE}.core.config")
    config.BinaryNinjaConfig = _BinaryNinjaConfig
    config.Config = _BinaryNinjaConfig
    string_utils = types.ModuleType(f"{FIXTURE_PACKAGE}.utils.string_utils")
    string_utils.escape_non_ascii = lambda value: value
    string_utils.parse_int_or_default = lambda value, default: (
        default if value is None else int(value)
    )
    number_utils = types.ModuleType(f"{FIXTURE_PACKAGE}.utils.number_utils")
    number_utils.convert_number = lambda value, _size=0: value

    synthetic_modules = {
        "binaryninja": binaryninja,
        "binaryninja.enums": enums,
        "binaryninja.settings": settings,
        FIXTURE_PACKAGE: package_root,
        f"{FIXTURE_PACKAGE}.api": api_package,
        f"{FIXTURE_PACKAGE}.core": core_package,
        f"{FIXTURE_PACKAGE}.server": server_package,
        f"{FIXTURE_PACKAGE}.utils": utils_package,
        f"{FIXTURE_PACKAGE}.core.config": config,
        f"{FIXTURE_PACKAGE}.utils.string_utils": string_utils,
        f"{FIXTURE_PACKAGE}.utils.number_utils": number_utils,
    }
    sys.modules.update(synthetic_modules)
    try:
        operations = _load_module(
            f"{FIXTURE_PACKAGE}.core.binary_operations",
            REPO_ROOT / "plugin/core/binary_operations.py",
        )
        endpoints = _load_module(
            f"{FIXTURE_PACKAGE}.api.endpoints",
            REPO_ROOT / "plugin/api/endpoints.py",
        )
        server = _load_module(
            f"{FIXTURE_PACKAGE}.server.http_server",
            REPO_ROOT / "plugin/server/http_server.py",
        )
        return operations, endpoints, server
    finally:
        for name, module in saved_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


binary_operations, endpoint_module, server_module = _load_selector_modules()


class _FakeFile:
    def __init__(self, filename: str):
        self.filename = filename


class _FakeView:
    def __init__(self, filename: str):
        self.file = _FakeFile(filename)


class _FakeInstruction:
    def __init__(self, address: int, text: str):
        self.address = address
        self.text = text

    def __str__(self):
        return self.text


class _FakeIl:
    def __init__(self, *instructions: _FakeInstruction):
        self.instructions = list(instructions)


class _FakeFunction:
    def __init__(self):
        self.name = "target"
        self.start = 0x1000
        self.analysis_skipped = True
        self.hlil = _FakeIl(_FakeInstruction(0x1000, "return 1"))
        self.mlil = _FakeIl(_FakeInstruction(0x1004, "var_0 = 1"))
        self.llil = _FakeIl(_FakeInstruction(0x1008, "LLIL_RET(1)"))


class _FunctionView(_FakeView):
    def __init__(self, function: _FakeFunction):
        super().__init__("/fixtures/function.bin")
        self.functions = [function]
        self.whole_view_waits = 0

    def get_function_at(self, address: int):
        if address == self.functions[0].start:
            return self.functions[0]
        return None

    def get_symbol_by_raw_name(self, _name: str):
        return None

    def update_analysis_and_wait(self):
        self.whole_view_waits += 1
        raise AssertionError("function-local IL must not wait for the whole BinaryView")


class MultiBinarySelectorTests(unittest.TestCase):
    def _operations(self, *filenames: str):
        operations = binary_operations.BinaryOperations(_BinaryNinjaConfig())
        views = [_FakeView(filename) for filename in filenames]
        for view in views:
            operations.current_view = view
        return operations, views

    def test_setting_a_new_gui_view_registers_before_it_becomes_current(self):
        operations = binary_operations.BinaryOperations(_BinaryNinjaConfig())
        view = _FakeView("/fixtures/newly-opened.bin")

        operations.current_view = view

        self.assertIs(operations.current_view, view)
        self.assertEqual(
            operations.list_open_binaries(),
            [
                {
                    "id": "1",
                    "filename": "/fixtures/newly-opened.bin",
                    "active": True,
                }
            ],
        )

    def test_numeric_view_ids_and_sorted_ordinals_have_distinct_namespaces(self):
        operations, views = self._operations(
            "/fixtures/z-last.bin",
            "/fixtures/a-first.bin",
        )
        endpoints = endpoint_module.BinaryNinjaEndpoints(operations)

        listing = endpoints.list_binaries()["binaries"]
        self.assertEqual(listing[0]["filename"], "/fixtures/a-first.bin")
        self.assertEqual(listing[0]["ordinal_selector"], "ordinal:1")
        self.assertEqual(listing[0]["view_selector"], "view:2")
        self.assertIn("ordinal:1", listing[0]["selectors"])
        self.assertIn("view:2", listing[0]["selectors"])
        self.assertNotIn("1", listing[0]["selectors"])
        self.assertNotIn("2", listing[0]["selectors"])

        selected_view = operations.select_view("view:2")
        self.assertIsNotNone(selected_view)
        self.assertIs(operations.current_view, views[1])

        selected_ordinal = operations.select_view("ordinal:1")
        self.assertIsNotNone(selected_ordinal)
        self.assertIs(operations.current_view, views[1])

        self.assertIsNone(operations.select_view("1"))
        self.assertIsNone(operations.select_view("2"))

    def test_duplicate_basename_is_neither_advertised_nor_selectable(self):
        operations, views = self._operations(
            "/fixtures/one/shared.bin",
            "/fixtures/two/shared.bin",
        )
        listing = endpoint_module.BinaryNinjaEndpoints(operations).list_binaries()["binaries"]

        self.assertEqual(len(listing), 2)
        for entry in listing:
            self.assertNotIn("shared.bin", entry["selectors"])
            self.assertIn(entry["filename"], entry["selectors"])
        self.assertIsNotNone(operations.select_view("view:2"))
        current_before = operations.current_view
        self.assertIsNone(operations.select_view("shared.bin"))
        self.assertIs(operations.current_view, current_before)
        self.assertIn(current_before, views)


class FunctionIlSchedulingTests(unittest.TestCase):
    def setUp(self):
        self.function = _FakeFunction()
        self.view = _FunctionView(self.function)
        self.operations = binary_operations.BinaryOperations(_BinaryNinjaConfig())
        self.operations.current_view = self.view

    def test_decompile_uses_on_demand_function_il_without_a_whole_view_wait(self):
        result = self.operations.decompile_function("target")

        self.assertEqual(result, "00001000        return 1")
        self.assertFalse(self.function.analysis_skipped)
        self.assertEqual(self.view.whole_view_waits, 0)

    def test_il_uses_on_demand_function_il_without_a_whole_view_wait(self):
        result = self.operations.get_function_il("target", view="mlil")

        self.assertEqual(result, "00001004        var_0 = 1")
        self.assertFalse(self.function.analysis_skipped)
        self.assertEqual(self.view.whole_view_waits, 0)


class ExplicitTargetGuardTests(unittest.TestCase):
    def _handler(
        self,
        operations,
        path: str,
        target: str = "",
        encoded_target: str = "",
    ):
        handler = server_module.MCPRequestHandler.__new__(server_module.MCPRequestHandler)
        handler.binary_ops = operations
        handler.auth_token = None
        handler.path = path
        handler.headers = {}
        if target:
            handler.headers["X-Binary-Ninja-View"] = target
        if encoded_target:
            handler.headers["X-Binary-Ninja-View-B64"] = encoded_target
        handler.responses = []
        handler._send_json_response = lambda payload, status_code=200: handler.responses.append(
            (status_code, payload)
        )
        return handler

    def test_multi_view_analysis_request_without_target_fails_closed(self):
        operations, _views = MultiBinarySelectorTests()._operations(
            "/fixtures/one.bin",
            "/fixtures/two.bin",
        )
        handler = self._handler(operations, "/status")

        self.assertFalse(handler._prepare_request())
        self.assertEqual(handler.responses[0][0], 409)
        self.assertIn("binary", str(handler.responses[0][1]).lower())

    def test_multi_view_session_endpoints_remain_unscoped(self):
        operations, _views = MultiBinarySelectorTests()._operations(
            "/fixtures/one.bin",
            "/fixtures/two.bin",
        )
        for path in (
            "/binaries",
            "/views",
            "/selectBinary",
            "/load",
            "/convertNumber",
            "/platforms",
        ):
            with self.subTest(path=path):
                handler = self._handler(operations, path)
                self.assertTrue(handler._prepare_request())
                self.assertEqual(handler.responses, [])

    def test_explicit_namespaced_target_is_accepted_with_multiple_views(self):
        operations, views = MultiBinarySelectorTests()._operations(
            "/fixtures/one.bin",
            "/fixtures/two.bin",
        )
        handler = self._handler(operations, "/status", target="view:1")

        self.assertTrue(handler._prepare_request())
        self.assertEqual(handler.responses, [])
        self.assertIs(operations.current_view, views[0])

    def test_single_view_request_remains_backward_compatible_without_target(self):
        operations, _views = MultiBinarySelectorTests()._operations("/fixtures/only.bin")
        handler = self._handler(operations, "/status")

        self.assertTrue(handler._prepare_request())
        self.assertEqual(handler.responses, [])

    def test_unicode_filename_decodes_and_selects_the_exact_view(self):
        unicode_path = "/fixtures/着色器/šhader.bin"
        operations, views = MultiBinarySelectorTests()._operations(
            "/fixtures/other.bin",
            unicode_path,
        )
        encoded = base64.urlsafe_b64encode(unicode_path.encode("utf-8")).decode("ascii")
        handler = self._handler(
            operations,
            "/status",
            encoded_target=encoded,
        )

        self.assertTrue(handler._prepare_request())
        self.assertEqual(handler.responses, [])
        self.assertIs(operations.current_view, views[1])


class LoadJournalTests(unittest.TestCase):
    def _handler(self, params: dict[str, object], view_id: str = "7"):
        events: list[tuple] = []
        view = types.SimpleNamespace(
            file=types.SimpleNamespace(filename="/fixtures/target.bin"),
            platform=types.SimpleNamespace(name="linux-x86_64"),
            start=0x1000,
            end=0x2000,
        )
        operations = types.SimpleNamespace(
            load_binary=lambda *_args, **_kwargs: view,
            register_view=lambda _view: view_id,
        )
        handler = server_module.MCPRequestHandler.__new__(server_module.MCPRequestHandler)
        handler.path = "/load"
        handler.binary_ops = operations
        handler._prepare_request = lambda: True
        handler._parse_post_params = lambda: dict(params)
        handler._send_json_response = lambda payload, status_code=200: events.append(
            ("response", status_code, payload)
        )
        return handler, events

    def test_load_journal_records_exact_view_id_before_success_response(self):
        params = {
            "filepath": "/fixtures/target.bin",
            "analysis_mode": "full",
            "platform": "linux-x86_64",
            "image_base": "0x1000",
        }
        handler, events = self._handler(params)
        handler.binary_loaded_callback = lambda payload, view_id: events.append(
            ("journal", payload, view_id)
        )

        handler._do_POST()

        self.assertEqual(events[0], ("journal", params, "7"))
        self.assertEqual(events[1][0:2], ("response", 200))
        self.assertEqual(events[1][2]["view_id"], "7")

    def test_load_rejects_shifted_view_id_before_journal_or_success(self):
        params = {
            "filepath": "/fixtures/target.bin",
            "analysis_mode": "basic",
            "platform": "",
            "image_base": "",
            "view_id": 1,
        }
        handler, events = self._handler(params, view_id="2")
        callback = mock.Mock()
        handler.binary_loaded_callback = callback

        handler._do_POST()

        callback.assert_not_called()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0:2], ("response", 500))
        self.assertIn("expected view:1, got view:2", events[0][2]["error"])

    def test_server_handler_does_not_descriptor_bind_plain_load_callback(self):
        events: list[tuple[dict[str, object], str | int]] = []

        def callback(payload: dict[str, object], view_id: str | int) -> None:
            events.append((payload, view_id))

        server = server_module.MCPServer.__new__(server_module.MCPServer)
        server.config = types.SimpleNamespace(
            server=types.SimpleNamespace(host="127.0.0.1", port=0)
        )
        server.server = None
        server.thread = None
        server.instance_id = "instance-12345678"
        server.auth_token = "token"
        server.binary_loaded_callback = callback
        server.operation_lock = server_module.threading.RLock()
        server.binary_ops = object()

        server.start()
        try:
            handler_class = server.server.RequestHandlerClass
            handler = handler_class.__new__(handler_class)
            handler.binary_loaded_callback({"filepath": "/target.bin"}, "7")
        finally:
            server.stop()

        self.assertEqual(events, [({"filepath": "/target.bin"}, "7")])


if __name__ == "__main__":
    unittest.main()
