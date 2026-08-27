#!/usr/bin/env python3
"""Protocol-level smoke test for the headless Binary Ninja MCP launcher."""

from __future__ import annotations

import argparse
import json
import select
import subprocess
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default="python3.13")
    parser.add_argument("--binary", default=str(REPO_ROOT / "example/chal"))
    parser.add_argument(
        "--open-binary",
        help="call the open_binary MCP tool for this path after startup",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="explicit HTTP port (default: launcher requests an atomic OS-assigned port)",
    )
    parser.add_argument(
        "--regressions",
        action="store_true",
        help="Exercise the MCP bridge regressions using the sieusb.ko fixture",
    )
    args = parser.parse_args()
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
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin and process.stdout and process.stderr

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
        content = result.get("content") or []
        if not content or content[0].get("type") != "text":
            raise RuntimeError(f"Tool {name} returned no text: {result}")
        return content[0].get("text", "")

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
    status = call_tool("get_binary_status")

    opened_status = ""
    scoped_statuses: dict[str, str] = {}
    open_elapsed = 0.0
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

    tools = tools_response["result"]["tools"]
    if not any(tool["name"] == "open_binary" for tool in tools):
        raise RuntimeError("open_binary was not advertised by tools/list")
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
    if opened_status:
        print(f"open_elapsed={open_elapsed:.3f}s")
        print(f"opened_status={opened_status}")
        print(f"scoped_targets={','.join(scoped_statuses)}")
    if regression_results:
        print(f"regressions={','.join(regression_results)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
