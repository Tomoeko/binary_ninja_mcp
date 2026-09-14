#!/usr/bin/env python3
"""Protocol-level smoke test for the headless Binary Ninja MCP launcher."""

from __future__ import annotations

import argparse
import atexit
import json
import os
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from bridge.native_v6_tools import NATIVE_V6_TOOL_NAMES  # noqa: E402


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_pids(pids: set[int], timeout: float) -> set[int]:
    deadline = time.monotonic() + timeout
    remaining = {pid for pid in pids if _pid_alive(pid)}
    while remaining and time.monotonic() < deadline:
        time.sleep(0.05)
        remaining = {pid for pid in remaining if _pid_alive(pid)}
    return remaining


def _runtime_host_pids(runtime_root: Path) -> set[int]:
    pids: set[int] = set()
    for state_file in runtime_root.glob("*/host.json"):
        try:
            payload = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        pid = payload.get("pid") if isinstance(payload, dict) else None
        if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
            pids.add(pid)
    return pids


def _stop_test_hosts(pids: set[int]) -> None:
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    remaining = _wait_for_pids(pids, 3.0)
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    _wait_for_pids(remaining, 3.0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default="python3.13")
    parser.add_argument("--binary", default=str(REPO_ROOT / "example/chal"))
    parser.add_argument(
        "--open-binary",
        help="call the open_binary MCP tool for this path after startup",
    )
    parser.add_argument(
        "--close-opened",
        action="store_true",
        help="close the --open-binary target and verify the original remains",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="explicit HTTP port (default: launcher requests an atomic OS-assigned port)",
    )
    parser.add_argument(
        "--shared-runtime-root",
        help="reuse this shared-host registry instead of creating an isolated one",
    )
    parser.add_argument(
        "--concurrency-barrier",
        help="two-phase filesystem barrier used by the shared-host concurrency smoke",
    )
    parser.add_argument(
        "--barrier-participants",
        type=int,
        default=0,
        help="number of clients expected at --concurrency-barrier",
    )
    parser.add_argument(
        "--regressions",
        action="store_true",
        help="Exercise the MCP bridge regressions using the sieusb.ko fixture",
    )
    parser.add_argument(
        "--native-regressions",
        action="store_true",
        help="Exercise native v6 lifecycle and editing calls on a temporary binary copy",
    )
    args = parser.parse_args()
    if bool(args.concurrency_barrier) != bool(args.barrier_participants):
        parser.error("--concurrency-barrier and --barrier-participants must be used together")
    if args.barrier_participants == 1 or args.barrier_participants < 0:
        parser.error("--barrier-participants must be at least 2")
    command = [
        args.python,
        str(REPO_ROOT / "scripts/run_headless_mcp.py"),
        "--binary",
        str(Path(args.binary).resolve()),
        "--startup-timeout",
        "30",
    ]
    if args.port:
        command.extend(["--port", str(args.port)])
    environment = os.environ.copy()
    shared_runtime = None
    if args.shared_runtime_root:
        runtime_root = Path(args.shared_runtime_root).resolve()
        runtime_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        environment["BINJA_MCP_SHARED_RUNTIME_ROOT"] = str(runtime_root)
    else:
        shared_runtime = tempfile.TemporaryDirectory(prefix="binary-ninja-mcp-runtime-")
        runtime_root = Path(shared_runtime.name)
        environment["BINJA_MCP_SHARED_RUNTIME_ROOT"] = str(runtime_root)
    environment["BINJA_MCP_SHARED_HOST_IDLE_SEC"] = "1"
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    assert process.stdin and process.stdout and process.stderr
    native_temp_dir = None
    observed_host_pids: set[int] = set()

    def cleanup() -> None:
        owned_host_pids = set(observed_host_pids)
        if shared_runtime is not None:
            owned_host_pids.update(_runtime_host_pids(runtime_root))
        if process.poll() is None:
            try:
                process.stdin.close()
            except OSError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        if shared_runtime is not None:
            remaining_hosts = _wait_for_pids(owned_host_pids, 8.0)
            if remaining_hosts:
                _stop_test_hosts(remaining_hosts)
        if native_temp_dir is not None:
            native_temp_dir.cleanup()
        if shared_runtime is not None:
            shared_runtime.cleanup()

    atexit.register(cleanup)

    responses: list[dict] = []

    def exchange(message: dict, timeout: int = 45) -> dict | None:
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()
        if "id" not in message:
            return None
        readable, _, _ = select.select([process.stdout], [], [], timeout)
        if not readable:
            raise TimeoutError(f"Timed out waiting for MCP response {message['id']}")
        line = process.stdout.readline()
        if not line:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            diagnostics = process.stderr.read() if process.poll() is not None else ""
            raise RuntimeError(
                "MCP launcher closed stdout before replying "
                f"(exit={process.poll()})\n{diagnostics[-5000:]}"
            )
        response = json.loads(line)
        responses.append(response)
        return response

    next_id = 1

    def request(method: str, params: dict, timeout: int = 45) -> dict:
        nonlocal next_id
        response = exchange(
            {"jsonrpc": "2.0", "id": next_id, "method": method, "params": params},
            timeout,
        )
        next_id += 1
        assert response is not None
        if response.get("error"):
            raise RuntimeError(f"MCP {method} failed: {response['error']}")
        return response

    def call_tool(name: str, arguments: dict | None = None, timeout: int = 45) -> str:
        response = request("tools/call", {"name": name, "arguments": arguments or {}}, timeout)
        result = response.get("result") or {}
        if result.get("isError"):
            raise RuntimeError(f"Tool {name} failed: {result}")
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            if name not in NATIVE_V6_TOOL_NAMES and set(structured) == {"result"}:
                value = structured["result"]
                return value if isinstance(value, str) else json.dumps(value)
            return json.dumps(structured)
        content = result.get("content") or []
        if not content or content[0].get("type") != "text":
            raise RuntimeError(f"Tool {name} returned no text: {result}")
        return content[0].get("text", "")

    def synchronize_concurrent_clients(binary: str) -> list[str]:
        if not args.concurrency_barrier:
            return []
        barrier = Path(args.concurrency_barrier).resolve()
        barrier.mkdir(mode=0o700, parents=True, exist_ok=True)
        client_id = str(os.getpid())

        opened = json.loads(
            call_tool(
                "bn_open_item_open",
                {"path": binary, "kind": "file", "setActive": False},
            )
        )
        open_item = opened.get("openItem")
        opened_path = open_item.get("path") if isinstance(open_item, dict) else None
        if not isinstance(opened_path, str) or (
            os.path.realpath(opened_path) != os.path.realpath(binary)
        ):
            raise RuntimeError(
                f"Concurrency client opened the wrong target: {opened_path!r} != {binary}"
            )

        def publish(phase: str) -> None:
            destination = barrier / f"{phase}-{client_id}"
            temporary = barrier / f".{phase}-{client_id}.tmp"
            temporary.write_text(binary, encoding="utf-8")
            temporary.replace(destination)

        def wait_for(phase: str) -> list[Path]:
            deadline = time.monotonic() + 60.0
            while time.monotonic() < deadline:
                markers = sorted(barrier.glob(f"{phase}-*"))
                if len(markers) >= args.barrier_participants:
                    return markers
                time.sleep(0.05)
            raise TimeoutError(
                f"Timed out at concurrency barrier {phase}: expected={args.barrier_participants}"
            )

        publish("ready")
        ready_markers = wait_for("ready")
        expected = {
            str(Path(marker.read_text(encoding="utf-8")).resolve()) for marker in ready_markers
        }
        if len(expected) != args.barrier_participants:
            raise RuntimeError(f"Concurrency barrier targets are not distinct: {expected}")
        open_items = json.loads(call_tool("bn_open_item_list")).get("openItems", [])
        resident = {
            str(Path(item["path"]).resolve())
            for item in open_items
            if isinstance(item, dict) and isinstance(item.get("path"), str)
        }
        missing = sorted(expected - resident)
        if missing:
            raise RuntimeError(
                "Shared host evicted explicitly targeted views before the barrier: "
                f"missing={missing}, resident={sorted(resident)}"
            )
        publish("verified")
        wait_for("verified")
        return sorted(expected)

    request(
        "initialize",
        {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "headless-smoke", "version": "1"},
        },
    )
    exchange({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    tools_response = request("tools/list", {})
    startup_binary = str(Path(args.binary).resolve())
    concurrency_inventory = synchronize_concurrent_clients(startup_binary)
    status = call_tool("get_binary_status", {"binary": startup_binary})
    parsed_initial_status = json.loads(status)
    host_pid = parsed_initial_status.get("pid")
    if isinstance(host_pid, int) and not isinstance(host_pid, bool) and host_pid > 0:
        observed_host_pids.add(host_pid)
    if parsed_initial_status.get("native_mcp_tool_count") != len(NATIVE_V6_TOOL_NAMES):
        raise RuntimeError(f"Native MCP compatibility status is incomplete: {status}")
    backend_names = set(parsed_initial_status.get("native_mcp_tools") or [])
    if backend_names != NATIVE_V6_TOOL_NAMES:
        raise RuntimeError(
            "Native MCP bridge/backend catalogs differ: "
            f"missing={sorted(NATIVE_V6_TOOL_NAMES - backend_names)}, "
            f"extra={sorted(backend_names - NATIVE_V6_TOOL_NAMES)}"
        )
    structured_native = request(
        "tools/call",
        {
            "name": "bn_analysis_status",
            "arguments": {"binary": startup_binary},
        },
    )["result"]
    if not isinstance(structured_native.get("structuredContent"), dict):
        raise RuntimeError(f"Native structured MCP result is missing: {structured_native}")

    native_results: dict[str, str] = {}
    for native_name, native_arguments in (
        ("bn_open_item_list", {}),
        ("bn_binary_view_get_active", {}),
        ("bn_binary_view_triage", {"binary": startup_binary}),
        ("bn_analysis_status", {"binary": startup_binary}),
        ("bn_entry_point_list", {"binary": startup_binary, "limit": 5}),
        ("bn_import_list", {"binary": startup_binary, "limit": 100}),
        ("bn_export_list", {"binary": startup_binary, "limit": 100}),
        ("bn_section_list", {"binary": startup_binary, "limit": 5}),
        ("bn_function_list", {"binary": startup_binary, "limit": 5}),
    ):
        native_result = call_tool(native_name, native_arguments)
        native_results[native_name] = native_result
        try:
            parsed_native_result = json.loads(native_result)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Native tool {native_name} did not return JSON: {native_result}"
            ) from exc
        if isinstance(parsed_native_result, dict) and parsed_native_result.get("error"):
            raise RuntimeError(f"Native tool {native_name} failed: {native_result}")

    entry_points = json.loads(native_results["bn_entry_point_list"])
    if not entry_points.get("entryPoints"):
        raise RuntimeError(f"Native entry-point lookup failed: {entry_points}")
    entry_address = entry_points["entryPoints"][0]["address"]
    imports = json.loads(native_results["bn_import_list"])["imports"]
    if any(
        item.get("type")
        not in {"ImportAddressSymbol", "ImportedFunctionSymbol", "ImportedDataSymbol"}
        for item in imports
    ):
        raise RuntimeError(f"Native import filtering leaked a non-import symbol: {imports}")
    binding_import_query = json.loads(
        call_tool(
            "bn_import_list",
            {"binary": startup_binary, "query": "GlobalBinding", "limit": 100},
        )
    )
    if binding_import_query.get("total") != 0:
        raise RuntimeError(f"Native import query searched non-name fields: {binding_import_query}")
    exports = json.loads(native_results["bn_export_list"])["exports"]
    if any(item.get("binding") not in {"GlobalBinding", "WeakBinding"} for item in exports):
        raise RuntimeError(f"Native export filtering leaked a local symbol: {exports}")
    binding_export_query = json.loads(
        call_tool(
            "bn_export_list",
            {"binary": startup_binary, "query": "GlobalBinding", "limit": 100},
        )
    )
    if binding_export_query.get("total") != 0:
        raise RuntimeError(f"Native export query searched non-name fields: {binding_export_query}")
    type_list = json.loads(
        call_tool("bn_type_list", {"binary": startup_binary, "limit": 1000})
    ).get("types", [])
    if type_list:
        selected_type = next(
            (item for item in type_list if item.get("class") == "StructureTypeClass"),
            type_list[0],
        )
        type_info = json.loads(
            call_tool(
                "bn_type_info",
                {"binary": startup_binary, "type": selected_type["name"]},
            )
        )
        required_type_fields = {
            "type",
            "id",
            "class",
            "definition",
            "width",
            "alignment",
            "autoDefined",
            "source",
            "outgoingDirectTypeReferences",
            "incomingDirectTypeReferences",
        }
        if not required_type_fields.issubset(type_info):
            raise RuntimeError(f"Native type-info shape is incomplete: {type_info}")
        if selected_type.get("class") == "StructureTypeClass" and "structureType" not in type_info:
            raise RuntimeError(f"Native structure type-info omitted structureType: {type_info}")
        native_results["bn_type_info"] = json.dumps(type_info)
    function_info = call_tool(
        "bn_function_info",
        {"function": entry_address, "binary": startup_binary},
    )
    if json.loads(function_info).get("error"):
        raise RuntimeError(f"Native default-architecture function lookup failed: {function_info}")
    native_results["bn_function_info"] = function_info
    decompiled = call_tool(
        "bn_function_decompile",
        {"function": entry_address, "binary": startup_binary, "limit": 5},
    )
    decompiled_json = json.loads(decompiled)
    if decompiled_json.get("language") != "Pseudo C" or not decompiled_json.get("lines"):
        raise RuntimeError(f"Native Pseudo C decompilation failed: {decompiled}")
    native_results["bn_function_decompile"] = decompiled

    reopened = call_tool(
        "bn_open_item_open",
        {"path": startup_binary, "kind": "file", "setActive": True},
    )
    reopened_json = json.loads(reopened)
    if reopened_json.get("error") or reopened_json.get("changed") is not False:
        raise RuntimeError(f"Native idempotent open failed: {reopened}")
    native_results["bn_open_item_open"] = reopened

    invalid_native = request(
        "tools/call",
        {
            "name": "bn_function_info",
            "arguments": {
                "function": "0xffffffffffffffff",
                "binary": startup_binary,
            },
        },
    )["result"]
    if not invalid_native.get("isError"):
        raise RuntimeError(f"Native domain error was reported as MCP success: {invalid_native}")
    invalid_text = " ".join(item.get("text", "") for item in invalid_native.get("content", []))
    if "function_not_found" not in invalid_text:
        raise RuntimeError(f"Native domain error lost its stable code: {invalid_native}")

    for invalid_arguments in ({"bogus": 1}, {"limit": "1"}):
        invalid_schema_result = request(
            "tools/call",
            {"name": "bn_function_list", "arguments": invalid_arguments},
        )["result"]
        if not invalid_schema_result.get("isError"):
            raise RuntimeError(
                "Native MCP accepted arguments rejected by the v6 schema: "
                f"{invalid_arguments!r} -> {invalid_schema_result!r}"
            )

    native_regression_results: dict[str, str] = {}
    if args.native_regressions:
        native_temp_dir = tempfile.TemporaryDirectory(prefix="binary-ninja-mcp-native-")
        native_target = Path(native_temp_dir.name) / Path(args.binary).name
        shutil.copy2(Path(args.binary).resolve(), native_target)
        opened_native = call_tool(
            "bn_open_item_open",
            {"path": str(native_target), "kind": "file", "setActive": False},
        )
        opened_native_json = json.loads(opened_native)
        if opened_native_json.get("error"):
            raise RuntimeError(f"Native open failed: {opened_native}")
        open_item = opened_native_json["openItem"]["handle"]
        native_regression_results["open"] = open_item

        unchanged_active = json.loads(call_tool("bn_binary_view_get_active"))
        if unchanged_active.get("binaryView", {}).get("filename") != startup_binary:
            raise RuntimeError(f"Native setActive=false changed selection: {unchanged_active}")
        preferred = next(
            (
                item
                for item in opened_native_json["binaryViews"]
                if item.get("recommended") and item.get("created")
            ),
            None,
        )
        if preferred is None:
            raise RuntimeError(f"Native open returned no recommended BinaryView: {opened_native}")
        activated = json.loads(
            call_tool("bn_binary_view_set_active", {"binaryView": preferred["handle"]})
        )
        binary_view = activated["binaryView"]["handle"]
        native_regression_results["set_active"] = activated["binaryView"]["viewType"]

        listed_views = json.loads(call_tool("bn_binary_view_list"))["binaryViews"]
        raw_candidate = next(
            (
                item
                for item in listed_views
                if item.get("openItem") == open_item
                and item.get("viewType") == "Raw"
                and not item.get("active")
            ),
            None,
        )
        if raw_candidate is not None:
            raw_active = json.loads(
                call_tool(
                    "bn_binary_view_set_active",
                    {"binaryView": raw_candidate["handle"]},
                )
            )
            if raw_active.get("binaryView", {}).get("viewType") != "Raw":
                raise RuntimeError(f"Native Raw view activation failed: {raw_active}")
            raw_handle = raw_active["binaryView"]["handle"]
            host_pid = int(
                json.loads(call_tool("get_binary_status", {"binary": raw_handle}))["pid"]
            )
            os.kill(host_pid, signal.SIGKILL)
            reset_result = request(
                "tools/call",
                {"name": "bn_binary_view_get_active", "arguments": {}},
                timeout=45,
            )["result"]
            reset_text = " ".join(item.get("text", "") for item in reset_result.get("content", []))
            if not reset_result.get("isError") or "native_session_reset" not in reset_text:
                raise RuntimeError(
                    f"Native host recovery silently changed session semantics: {reset_result}"
                )
            refreshed = json.loads(call_tool("bn_binary_view_list"))["binaryViews"]
            preferred_candidate = next(
                item
                for item in refreshed
                if item.get("openItem") == open_item
                and item.get("viewType") == preferred["viewType"]
            )
            restored = json.loads(
                call_tool(
                    "bn_binary_view_set_active",
                    {"binaryView": preferred_candidate["handle"]},
                )
            )
            binary_view = restored["binaryView"]["handle"]
            native_regression_results["view_candidates"] = "Raw"
            native_regression_results["session_reset"] = "fail-closed"

        call_tool(
            "bn_analysis_update_and_wait",
            {"binary": binary_view},
            timeout=45,
        )
        native_entry_points = json.loads(
            call_tool("bn_entry_point_list", {"binary": binary_view, "limit": 1})
        )
        if not native_entry_points.get("entryPoints"):
            raise RuntimeError(f"Native entry-point lookup failed: {native_entry_points}")
        entry_address = native_entry_points["entryPoints"][0]["address"]

        variables = json.loads(
            call_tool(
                "bn_variable_list",
                {"binary": binary_view, "function": entry_address, "limit": 100},
            )
        ).get("variables", [])
        editable_variable = next(
            (
                variable
                for variable in variables
                if variable.get("name")
                and str(variable.get("sourceType", ""))
                in {"RegisterVariableSourceType", "StackVariableSourceType"}
            ),
            None,
        )
        if editable_variable is None:
            raise RuntimeError(f"Native smoke fixture has no editable variable: {variables}")
        original_variable = str(editable_variable["name"])
        renamed_variable = "mcp_v6_smoke_variable"
        renamed_result = json.loads(
            call_tool(
                "bn_variable_rename",
                {
                    "binary": binary_view,
                    "function": entry_address,
                    "variable": original_variable,
                    "newName": renamed_variable,
                },
            )
        )
        if not renamed_result.get("changed"):
            raise RuntimeError(f"Native variable rename did not apply: {renamed_result}")
        typed_result = json.loads(
            call_tool(
                "bn_variable_set_type",
                {
                    "binary": binary_view,
                    "function": entry_address,
                    "variable": renamed_variable,
                    "definition": "char",
                },
            )
        )
        if typed_result.get("variable") != renamed_variable:
            raise RuntimeError(f"Sequential native variable edit failed: {typed_result}")
        native_regression_results["variable_edit"] = renamed_variable

        marker = "Binary Ninja MCP native v6 protocol smoke"
        call_tool(
            "bn_comment_set",
            {"binary": binary_view, "comment": entry_address, "text": marker},
        )
        comment = json.loads(
            call_tool(
                "bn_comment_get",
                {"binary": binary_view, "comment": entry_address},
            )
        )
        if comment.get("text") != marker:
            raise RuntimeError(f"Native comment round trip failed: {comment}")
        native_regression_results["comment"] = entry_address
        symbols_at = json.loads(
            call_tool(
                "bn_symbol_list_at",
                {"binary": binary_view, "address": entry_address},
            )
        )
        if not symbols_at.get("symbols"):
            raise RuntimeError(f"Native exact-address symbol lookup failed: {symbols_at}")
        native_regression_results["symbol_list_at"] = str(symbols_at["count"])
        call_tool(
            "bn_comment_delete",
            {"binary": binary_view, "comment": entry_address},
        )
        closed_native = json.loads(
            call_tool(
                "bn_open_item_close",
                {"openItem": open_item, "save": "discard"},
            )
        )
        if not closed_native.get("closed"):
            raise RuntimeError(f"Native close failed: {closed_native}")
        native_regression_results["close"] = "discard"

    opened_status = ""
    scoped_statuses: dict[str, str] = {}
    open_elapsed = 0.0
    close_result = ""
    if args.open_binary:
        open_path = Path(args.open_binary).resolve()
        started = time.monotonic()
        opened = call_tool("open_binary", {"filepath": str(open_path)}, timeout=15)
        open_elapsed = time.monotonic() - started
        if "background analysis started" not in opened:
            raise RuntimeError(f"open_binary returned an unexpected result: {opened}")
        opened_status = call_tool("get_binary_status", {"binary": str(open_path)})
        parsed_status = json.loads(opened_status)
        if parsed_status.get("filename") != str(open_path):
            raise RuntimeError(f"open_binary selected the wrong view: {opened_status}")

        for target in (Path(args.binary).resolve(), open_path):
            scoped = call_tool("get_binary_status", {"binary": str(target)})
            scoped_statuses[str(target)] = scoped
            parsed_scoped = json.loads(scoped)
            if parsed_scoped.get("filename") != str(target):
                raise RuntimeError(f"explicit binary selector targeted the wrong view: {scoped}")

        sidecar = open_path.with_suffix(".json")
        if sidecar.is_file():
            metadata = json.loads(sidecar.read_text(encoding="utf-8"))
            expected_base = metadata.get("base")
            if expected_base is None:
                expected_base = metadata.get("image_base")
            if expected_base is not None:
                expected_start = hex(int(str(expected_base), 0))
                if parsed_status.get("start") != expected_start:
                    raise RuntimeError(
                        "open_binary ignored sidecar image base: "
                        f"expected {expected_start}, got {parsed_status.get('start')}"
                    )
        if args.close_opened:
            close_result = call_tool("close_binary", {"view": str(open_path)})
            if "Binary closed:" not in close_result:
                raise RuntimeError(f"close_binary returned an unexpected result: {close_result}")
            remaining = call_tool(
                "get_binary_status",
                {"binary": str(Path(args.binary).resolve())},
            )
            if json.loads(remaining).get("filename") != str(Path(args.binary).resolve()):
                raise RuntimeError(f"close_binary removed the wrong view: {remaining}")

    regression_results: dict[str, str] = {}
    if args.regressions:
        regression_results["list_platforms"] = call_tool("list_platforms")
        regression_results["function_at"] = call_tool("function_at", {"address": "0x40035c"})
        regression_results["get_user_defined_type"] = call_tool(
            "get_user_defined_type", {"type_name": "__mcp_missing_type__"}
        )

        call_tool(
            "set_comment",
            {"address": "0x40035c", "comment": "headless MCP regression"},
        )
        regression_results["delete_comment"] = call_tool("delete_comment", {"address": "0x40035c"})
        call_tool(
            "set_function_comment",
            {"function_name": "alloc_ep_req", "comment": "headless MCP regression"},
        )
        regression_results["delete_function_comment"] = call_tool(
            "delete_function_comment", {"function_name": "alloc_ep_req"}
        )

        regression_results["rename_mapping"] = call_tool(
            "rename_multi_variables",
            {
                "function_identifier": "alloc_ep_req",
                "mapping_json": '{"arg_0":"arg_mapping"}',
            },
        )
        regression_results["rename_array"] = call_tool(
            "rename_multi_variables",
            {
                "function_identifier": "alloc_ep_req",
                "renames_json": '[{"old":"arg_mapping","new":"arg_array"}]',
            },
        )
        regression_results["rename_pairs"] = call_tool(
            "rename_multi_variables",
            {
                "function_identifier": "alloc_ep_req",
                "pairs": "arg_array:arg_pairs",
            },
        )

        if not regression_results["list_platforms"].strip():
            raise RuntimeError("list_platforms returned an empty result")
        if "alloc_ep_req" not in regression_results["function_at"]:
            raise RuntimeError(
                f"function_at returned an unexpected result: {regression_results['function_at']}"
            )
        for name in ("delete_comment", "delete_function_comment"):
            if "Successfully deleted" not in regression_results[name]:
                raise RuntimeError(f"{name} did not confirm deletion: {regression_results[name]}")
        for name in ("rename_mapping", "rename_array", "rename_pairs"):
            if "Batch rename: 1/1 applied" not in regression_results[name]:
                raise RuntimeError(f"{name} failed: {regression_results[name]}")

    process.stdin.close()
    process.wait(timeout=15)
    stderr = process.stderr.read()
    if process.returncode != 0:
        raise RuntimeError(
            f"MCP smoke test failed (exit={process.returncode})\n"
            f"responses={responses!r}\n{stderr[-3000:]}"
        )
    cleanup()
    atexit.unregister(cleanup)

    tools = tools_response["result"]["tools"]
    advertised_names = {tool["name"] for tool in tools}
    missing_native = sorted(NATIVE_V6_TOOL_NAMES - advertised_names)
    if missing_native:
        raise RuntimeError(f"Native Binary Ninja 6 tools were not advertised: {missing_native}")
    if not any(tool["name"] == "open_binary" for tool in tools):
        raise RuntimeError("open_binary was not advertised by tools/list")
    if not any(tool["name"] == "close_binary" for tool in tools):
        raise RuntimeError("close_binary was not advertised by tools/list")
    native_list_schema = next(
        tool["inputSchema"] for tool in tools if tool["name"] == "bn_function_list"
    )
    if native_list_schema.get("additionalProperties") is not False:
        raise RuntimeError("Native v6 input schemas are not closed objects")
    if native_list_schema["properties"]["limit"].get("maximum") != 1000:
        raise RuntimeError("Native v6 pagination schema lost its upper bound")
    decompile_schema = next(
        tool["inputSchema"] for tool in tools if tool["name"] == "decompile_function"
    )
    if "binary" not in decompile_schema.get("properties", {}):
        raise RuntimeError("analysis tools do not expose an explicit binary selector")
    status_schema = next(
        tool["inputSchema"] for tool in tools if tool["name"] == "get_binary_status"
    )
    if "binary" not in status_schema.get("properties", {}):
        raise RuntimeError("get_binary_status does not expose an explicit binary selector")
    print(f"responses={len(responses)}")
    print(f"tool_count={len(tools)}")
    print("open_binary=True")
    print(f"status={status}")
    print(f"native_tool_count={len(NATIVE_V6_TOOL_NAMES)}")
    print(f"native_smoke={','.join(native_results)}")
    if opened_status:
        print(f"open_elapsed={open_elapsed:.3f}s")
        print(f"opened_status={opened_status}")
        print(f"scoped_targets={','.join(scoped_statuses)}")
    if close_result:
        print(f"close_result={close_result}")
    if regression_results:
        print(f"regressions={','.join(regression_results)}")
    if native_regression_results:
        print(f"native_regressions={','.join(native_regression_results)}")
    if concurrency_inventory:
        print(f"concurrency_inventory={','.join(concurrency_inventory)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
