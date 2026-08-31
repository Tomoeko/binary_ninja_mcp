from __future__ import annotations

import base64
import importlib.util
import os
import sys
import tempfile
import threading
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
    def __init__(self, max_owned_views=None):
        self.max_owned_views = max_owned_views


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
        self.modified = False
        self.analysis_changed = False
        self.close_count = 0

    def close(self):
        self.close_count += 1


class _FakeView:
    def __init__(self, filename: str):
        self.file = _FakeFile(filename)


class _OwnedFakeView(_FakeView):
    def __init__(self, filename: str):
        super().__init__(filename)
        self.abort_count = 0
        self.exit_count = 0
        self.analysis_updates = 0
        self.platform = types.SimpleNamespace(name="test-platform")
        self.start = 0x1000
        self.end = 0x2000

    def abort_analysis(self):
        self.abort_count += 1

    def __exit__(self, _type, _value, _traceback):
        self.exit_count += 1
        self.file.close()

    def update_analysis(self):
        self.analysis_updates += 1


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


class HeadlessOwnedViewCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.paths = []
        for name in ("a.bin", "b.bin", "c.bin"):
            path = self.root / name
            path.write_bytes(name.encode("ascii"))
            self.paths.append(path)
        self.load_calls: list[str] = []
        self.loaded_views: list[_OwnedFakeView] = []

        def fake_load(filepath, *, update_analysis, options):
            self.assertFalse(update_analysis)
            self.assertIn("analysis.mode", options)
            self.load_calls.append(filepath)
            view = _OwnedFakeView(filepath)
            self.loaded_views.append(view)
            return view

        self.load_patch = mock.patch.object(binary_operations.bn, "load", side_effect=fake_load)
        self.load_patch.start()

    def tearDown(self):
        self.load_patch.stop()
        self.temporary.cleanup()

    def _operations(self, limit=2, callback=None):
        return binary_operations.BinaryOperations(
            _BinaryNinjaConfig(limit),
            owned_views_changed_callback=callback,
        )

    def test_exact_symlink_hardlink_and_concurrent_loads_share_one_view(self):
        symlink = self.root / "alias-symlink.bin"
        hardlink = self.root / "alias-hardlink.bin"
        symlink.symlink_to(self.paths[0])
        os.link(self.paths[0], hardlink)
        operations = self._operations()
        results: list[_OwnedFakeView] = []
        failures: list[BaseException] = []

        def load(path: Path):
            try:
                results.append(operations.load_binary(str(path)))
            except BaseException as exc:
                failures.append(exc)

        threads = [
            threading.Thread(target=load, args=(path,))
            for path in (self.paths[0], symlink, hardlink) * 8
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)

        self.assertFalse(failures)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(self.load_calls), 1)
        self.assertEqual(len({id(view) for view in results}), 1)
        self.assertEqual(operations.managed_view_count(), 1)
        self.assertEqual(self.loaded_views[0].analysis_updates, 1)
        self.assertIsNotNone(operations.select_view(str(hardlink)))

    def test_hardlink_creation_does_not_invalidate_a_resident_view(self):
        operations = self._operations()
        view = operations.load_binary(str(self.paths[0]))
        hardlink = self.root / "late-hardlink.bin"
        os.link(self.paths[0], hardlink)

        reused = operations.load_binary(str(hardlink))
        record = operations.owned_view_record(view)
        info = self.paths[0].stat()

        self.assertIs(reused, view)
        self.assertEqual(len(self.load_calls), 1)
        self.assertIsNotNone(record)
        self.assertEqual(
            record["source_identity"],
            {
                "device": info.st_dev,
                "inode": info.st_ino,
                "size": info.st_size,
                "mtime_ns": info.st_mtime_ns,
                "ctime_ns": info.st_ctime_ns,
            },
        )

    def test_source_change_during_native_load_closes_the_partial_view(self):
        operations = self._operations()
        partial = _OwnedFakeView(str(self.paths[0]))

        def mutate_during_load(*_args, **_kwargs):
            self.paths[0].write_bytes(b"changed-during-native-load")
            return partial

        with (
            mock.patch.object(
                binary_operations.bn,
                "load",
                side_effect=mutate_during_load,
            ),
            self.assertRaisesRegex(
                binary_operations.BinaryLoadConflict,
                "changed on disk while Binary Ninja was opening it",
            ),
        ):
            operations.load_binary(str(self.paths[0]))

        self.assertEqual(partial.exit_count, 1)
        self.assertEqual(operations.managed_view_count(), 0)

    def test_lru_touch_evicts_only_the_oldest_clean_view(self):
        snapshots = []
        operations = self._operations(
            callback=lambda records, next_id: snapshots.append(
                ([dict(record) for record in records], next_id)
            )
        )
        first = operations.load_binary(str(self.paths[0]))
        second = operations.load_binary(str(self.paths[1]))
        self.assertIsNotNone(operations.select_view("view:1"))

        third = operations.load_binary(str(self.paths[2]))

        self.assertEqual(second.abort_count, 1)
        self.assertEqual(second.exit_count, 1)
        self.assertEqual(second.file.close_count, 1)
        self.assertEqual(first.exit_count, 0)
        self.assertEqual(third.exit_count, 0)
        self.assertEqual(
            {item["filename"] for item in operations.list_open_binaries()},
            {os.path.realpath(self.paths[0]), os.path.realpath(self.paths[2])},
        )
        self.assertEqual(
            [record["filepath"] for record in snapshots[-1][0]],
            [os.path.realpath(self.paths[0]), os.path.realpath(self.paths[2])],
        )
        self.assertEqual(snapshots[-1][1], 4)

    def test_conflicting_load_options_and_replaced_source_fail_before_reload(self):
        operations = self._operations()
        operations.load_binary(str(self.paths[0]), analysis_mode="basic")

        with self.assertRaisesRegex(
            binary_operations.BinaryLoadConflict,
            "different immutable load settings",
        ):
            operations.load_binary(str(self.paths[0]), analysis_mode="full")
        self.assertEqual(len(self.load_calls), 1)

        self.paths[0].write_bytes(b"replacement-with-a-different-signature")
        with self.assertRaisesRegex(binary_operations.BinaryLoadConflict, "changed on disk"):
            operations.load_binary(str(self.paths[0]), analysis_mode="basic")
        self.assertEqual(len(self.load_calls), 1)

    def test_dirty_view_blocks_automatic_and_unconfirmed_explicit_close(self):
        operations = self._operations(limit=1)
        view = operations.load_binary(str(self.paths[0]))
        view.file.modified = True

        with self.assertRaisesRegex(RuntimeError, "unsaved changes"):
            operations.load_binary(str(self.paths[1]))
        self.assertEqual(len(self.load_calls), 1)
        with self.assertRaisesRegex(RuntimeError, "discard=true"):
            operations.close_owned_view("view:1")

        closed = operations.close_owned_view("view:1", discard=True)
        self.assertEqual(closed["filepath"], os.path.realpath(self.paths[0]))
        self.assertEqual(view.exit_count, 1)
        self.assertEqual(operations.managed_view_count(), 0)

    def test_analysis_changes_and_unreadable_dirty_state_block_close(self):
        operations = self._operations(limit=1)
        view = operations.load_binary(str(self.paths[0]))
        view.file.analysis_changed = True

        with self.assertRaisesRegex(RuntimeError, "unsaved changes"):
            operations.load_binary(str(self.paths[1]))
        with self.assertRaisesRegex(RuntimeError, "discard=true"):
            operations.close_owned_view("view:1")

        view.file.analysis_changed = False
        del view.file.analysis_changed
        self.assertTrue(operations._view_is_modified(view))

        view.file.analysis_changed = False
        del view.file.modified
        self.assertTrue(operations._view_is_modified(view))

        class UnreadableFileView:
            @property
            def file(self):
                raise RuntimeError("file metadata is unavailable")

        self.assertTrue(operations._view_is_modified(UnreadableFileView()))
        operations.close_owned_view("view:1", discard=True)
        self.assertEqual(view.exit_count, 1)

    def test_recovery_ids_keep_gaps_and_never_reuse_the_watermark(self):
        operations = self._operations()
        operations.reserve_next_view_id(7)
        first = operations.load_binary(str(self.paths[0]), preferred_view_id=3)
        second = operations.load_binary(str(self.paths[1]))

        self.assertEqual(operations._view_id(first), "3")
        self.assertEqual(operations._view_id(second), "7")
        self.assertEqual(
            [record["view_id"] for record in operations.owned_view_records()],
            [3, 7],
        )

    def test_suppressed_inventory_and_shutdown_are_deterministic(self):
        snapshots = []
        operations = self._operations(
            callback=lambda records, next_id: snapshots.append((records, next_id))
        )
        first = operations.load_binary(str(self.paths[0]), persist_inventory=False)
        second = operations.load_binary(str(self.paths[1]), persist_inventory=False)
        self.assertEqual(snapshots, [])

        operations.persist_owned_view_inventory()
        self.assertEqual(len(snapshots), 1)
        operations.close_owned_views()
        operations.close_owned_views()

        self.assertEqual(first.exit_count, 1)
        self.assertEqual(second.exit_count, 1)
        self.assertEqual(first.abort_count, 1)
        self.assertEqual(second.abort_count, 1)


class BoundedStringQueryTests(unittest.TestCase):
    def test_plain_page_decodes_only_page_sized_results(self):
        value_reads = 0

        class StringReference:
            start = 0x1000
            length = 4
            type = "AsciiString"

            @property
            def value(self):
                nonlocal value_reads
                value_reads += 1
                return "value"

        view = _FakeView("/fixtures/strings.bin")
        view.start = 0x1000
        view.end = 0x2000
        view.segments = []

        def ranged_strings(start, length):
            self.assertEqual((start, length), (0x1000, 0x1000))
            return [StringReference() for _ in range(1000)]

        view.get_strings = ranged_strings
        operations = binary_operations.BinaryOperations(_BinaryNinjaConfig())
        operations.current_view = view

        page = operations.get_strings(500, 3)

        self.assertEqual(len(page), 3)
        self.assertEqual(value_reads, 3)

    def test_filtered_query_keeps_only_the_page_but_reports_exact_total(self):
        references = [
            types.SimpleNamespace(
                start=0x1000 + index,
                length=len(value),
                type="AsciiString",
                value=value,
            )
            for index, value in enumerate(("hit-a", "miss", "hit-b", "hit-c"))
        ]
        view = _FakeView("/fixtures/strings.bin")
        view.start = 0x1000
        view.end = 0x2000
        view.segments = []
        view.get_strings = lambda start, length: [
            reference for reference in references if start <= reference.start < start + length
        ]
        operations = binary_operations.BinaryOperations(_BinaryNinjaConfig())
        operations.current_view = view

        page, total = operations.search_strings("hit", offset=1, limit=1)

        self.assertEqual(total, 3)
        self.assertEqual([item["value"] for item in page], ["hit-b"])

    def test_string_queries_use_only_bounded_mapped_ranges_and_keep_exact_semantics(self):
        references = [
            types.SimpleNamespace(
                start=address,
                length=len(value),
                type="AsciiString",
                value=value,
            )
            for address, value in (
                (0x1000, "miss-a"),
                (0x1003, "hit-a"),
                (0x1004, "hit-b"),
                (0x100B, "hit-c"),
                (0x2000, "miss-b"),
                (0x2004, "hit-d"),
            )
        ]
        view = _FakeView("/fixtures/strings.bin")
        view.start = 0x1000
        view.end = 0x3000
        # Deliberately unsorted and overlapping. The gap must not be scanned.
        view.segments = [
            types.SimpleNamespace(start=0x2000, end=0x2008),
            types.SimpleNamespace(start=0x1008, end=0x100C),
            types.SimpleNamespace(start=0x1000, end=0x100A),
        ]
        calls = []

        def ranged_strings(*args):
            # A regression to get_strings() without bounds fails immediately.
            self.assertEqual(len(args), 2)
            start, length = args
            calls.append((start, length))
            return [
                reference for reference in references if start <= reference.start < start + length
            ]

        view.get_strings = ranged_strings
        operations = binary_operations.BinaryOperations(_BinaryNinjaConfig())
        operations.current_view = view
        expected_calls = [
            (0x1000, 4),
            (0x1004, 4),
            (0x1008, 4),
            (0x2000, 4),
            (0x2004, 4),
        ]

        with mock.patch.object(binary_operations, "_STRING_SCAN_CHUNK_BYTES", 4):
            page = operations.get_strings(offset=2, limit=3)
            filtered, total = operations.search_strings("hit", offset=1, limit=2)

        self.assertEqual(
            [item["value"] for item in page],
            ["hit-b", "hit-c", "miss-b"],
        )
        self.assertEqual(total, 4)
        self.assertEqual(
            [item["value"] for item in filtered],
            ["hit-b", "hit-c"],
        )
        # get_strings stops once its page is full; search_strings traverses all
        # mapped chunks to produce an exact total.
        self.assertEqual(calls[:4], expected_calls[:4])
        self.assertEqual(calls[4:], expected_calls)
        self.assertTrue(all(length <= 4 for _start, length in calls))


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
            owns_path=lambda _path: False,
            owned_view_record=lambda _view: None,
            reserve_next_view_id=lambda _value: None,
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

    def test_inventory_sync_reserves_watermark_before_persisting(self):
        handler, events = self._handler({"next_view_id": 9})
        actions = []
        handler.path = "/syncInventory"
        handler.binary_ops.reserve_next_view_id = lambda value: actions.append(("reserve", value))
        handler.binary_ops.persist_owned_view_inventory = lambda: actions.append(("persist",))

        handler._do_POST()

        self.assertEqual(actions, [("reserve", 9), ("persist",)])
        self.assertEqual(events, [("response", 200, {"success": True})])

    def test_inventory_sync_requires_a_watermark(self):
        handler, events = self._handler({})
        handler.path = "/syncInventory"

        handler._do_POST()

        self.assertEqual(events[0][0:2], ("response", 400))
        self.assertIn("next_view_id", events[0][2]["error"])

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
