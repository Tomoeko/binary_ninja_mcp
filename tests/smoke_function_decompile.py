#!/usr/bin/env python3
"""Cold/warm native decompilation through a fresh headless MCP session.

Run with .venv/bin/python3; --python selects the Binary Ninja host interpreter.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import re
import tempfile
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from smoke_headless_mcp import _runtime_host_pids, _stop_test_hosts, _wait_for_pids

REPO_ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def failure_message(error: BaseException) -> str:
    """Expose SDK task-group failures instead of hiding their actual cause."""
    if isinstance(error, BaseExceptionGroup):
        return "; ".join(failure_message(child) for child in error.exceptions)
    return f"{type(error).__name__}: {error}"


def file_identity(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    require(
        (before.st_ino, before.st_size, before.st_mtime_ns)
        == (after.st_ino, after.st_size, after.st_mtime_ns),
        "Binary changed while hashing",
    )
    return {"bytes": before.st_size, "sha256": digest.hexdigest()}


class TimedTools:
    def __init__(self, session: ClientSession, timeout: float):
        self.session = session
        self.deadline = time.monotonic() + timeout
        self.dual_output_responses = 0

    async def call(self, name: str, arguments: dict | None = None, *, allow_error=False):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "Smoke deadline exceeded")
        result = await asyncio.wait_for(self.session.call_tool(name, arguments or {}), remaining)
        wire = result.model_dump(by_alias=True)
        texts = [item.text for item in result.content if item.type == "text"]
        require(bool(texts), "Tool returned no text: " + name)
        require(all(text.startswith(name + "\n\n") for text in texts), "Missing plaintext header")
        value = wire.get("structuredContent")
        require(isinstance(value, dict), "Tool returned no structured data: " + name)
        self.dual_output_responses += 1
        if not name.startswith("bn_") and set(value) == {"result"}:
            value = value["result"]
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                pass
        failed = wire.get("isError", False) or (
            isinstance(value, dict) and bool(value.get("error"))
        )
        require(allow_error or not failed, "Tool returned an error: " + name)
        return value


def text_summary(result: dict, address: str, seconds: float, language=None) -> dict:
    require(isinstance(result, dict), "Native text result must be an object")
    require(result.get("function", {}).get("address") == address, "Wrong function address")
    require(bool(result.get("text", "").strip()) and bool(result.get("lines")), "Empty native text")
    require(result.get("truncated") is False, "Function exceeds the 1,000-line smoke scope")
    require(language is None or result.get("language") == language, "Unexpected language")
    encoded = result["text"].encode()
    return {
        "seconds": seconds,
        "lines": len(result["lines"]),
        "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "analysis_enabled_on_demand": result.get("analysisEnabledOnDemand"),
        "warnings": [warning.get("code") for warning in result.get("warnings", [])],
    }


async def exercise(tools: TimedTools, binary: str, functions: list[str], extras: bool) -> dict:
    initial = await tools.call("get_binary_status", {"binary": binary})
    require(initial.get("filename") == binary, "Startup selected the wrong binary")
    initial_analysis = await tools.call("bn_analysis_status", {"binary": binary})
    binaries = await tools.call("list_binaries")
    require(isinstance(binaries, list) and bool(binaries), "Legacy inventory is empty")
    if extras:
        invalid = await tools.call(
            "bn_analysis_status", {"binary": binary, "unexpected": True}, allow_error=True
        )
        require(isinstance(invalid, dict) and "error" in invalid, "Missing structured tool error")
    observations = []
    for address in functions:
        selection = {"binary": binary, "function": address}
        started = time.monotonic()
        attempts = 0
        while True:
            attempts += 1
            info = await tools.call("bn_function_info", selection, allow_error=True)
            if isinstance(info, dict) and "function" in info:
                require(info["function"].get("address") == address, "Function resolved elsewhere")
                break
            error = info.get("error", {}) if isinstance(info, dict) else {}
            require(
                isinstance(error, dict) and error.get("code") == "function_not_found",
                "Unexpected function discovery error",
            )
            await asyncio.sleep(0.05)
        item = {
            "address": address,
            "discovery_attempts": attempts,
            "discovery_seconds": time.monotonic() - started,
        }
        texts = []
        for phase in ("cold", "warm"):
            started = time.monotonic()
            result = await tools.call("bn_function_decompile", {**selection, "limit": 1000})
            item[phase] = text_summary(result, address, time.monotonic() - started, "Pseudo C")
            texts.append(result["text"])
        item["stable"] = not item["cold"]["warnings"] and not item["warm"]["warnings"]
        item["text_equal"] = texts[0] == texts[1]
        require(not item["stable"] or item["text_equal"], "Stable cold/warm Pseudo C differs")
        if extras:
            started = time.monotonic()
            result = await tools.call(
                "bn_function_il", {**selection, "level": "hlil", "limit": 1000}
            )
            item["hlil"] = text_summary(result, address, time.monotonic() - started)
            started = time.monotonic()
            legacy = await tools.call("decompile_function", {"binary": binary, "name": address})
            prefix = "File: " + binary + "\n\n"
            require(isinstance(legacy, str) and legacy.startswith(prefix), "Wrong legacy binary")
            body = legacy[len(prefix) :]
            require(
                body.strip() and not body.startswith(("Error:", "Request failed:")),
                "Legacy decompile returned no code",
            )
            item["legacy"] = {
                "seconds": time.monotonic() - started,
                "bytes": len(body.encode()),
                "sha256": hashlib.sha256(body.encode()).hexdigest(),
            }
        observations.append(item)
    final = await tools.call("get_binary_status", {"binary": binary})
    require(final.get("filename") == binary, "Final status selected the wrong binary")
    return {
        "functions": observations,
        "host_pid": initial.get("pid"),
        "binary_ninja_version": initial.get("binary_ninja_version"),
        "initial_analysis": initial_analysis,
        "final_analysis": await tools.call("bn_analysis_status", {"binary": binary}),
    }


async def run(args) -> dict:
    binary = str(args.binary.expanduser().resolve(strict=True))
    source = file_identity(Path(binary))
    started = time.monotonic()
    summary = {
        "schema": 1,
        "passed": False,
        "binary": binary,
        "binary_identity": source,
        "analysis_mode": "basic",
        "whole_view_analysis_wait_requested": False,
    }
    with tempfile.TemporaryDirectory(prefix="binary-ninja-function-smoke-") as workspace:
        runtime = Path(workspace) / "runtime"
        runtime.mkdir()
        environment = os.environ.copy()
        environment.update(
            {
                "BINJA_MCP_SHARED_RUNTIME_ROOT": str(runtime),
                "BINJA_MCP_SHARED_HOST_IDLE_SEC": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "BINJA_MCP_FUNCTION_ANALYSIS_TIMEOUT_SEC": str(args.timeout),
                "BINJA_MCP_HTTP_READ_TIMEOUT_SEC": str(args.timeout + 5),
            }
        )
        server = StdioServerParameters(
            command=args.python,
            env=environment,
            args=[
                str(REPO_ROOT / "scripts/run_headless_mcp.py"),
                "--python",
                args.python,
                "--binary",
                binary,
                "--startup-timeout",
                str(min(30, args.timeout)),
            ],
        )
        host_pids = set()
        with (Path(workspace) / "stderr.log").open("w+") as diagnostics:
            try:
                async with stdio_client(server, errlog=diagnostics) as streams:
                    async with ClientSession(*streams) as session:
                        tools = TimedTools(session, args.timeout)
                        await asyncio.wait_for(session.initialize(), args.timeout)
                        try:
                            summary.update(
                                await exercise(tools, binary, args.functions, args.extras)
                            )
                            require(file_identity(Path(binary)) == source, "Source binary changed")
                            summary["passed"] = True
                        finally:
                            host_pids.update(_runtime_host_pids(runtime))
                            tools.deadline = time.monotonic() + 5
                            closed = await tools.call(
                                "close_binary", {"view": binary, "discard": True}
                            )
                            require(
                                isinstance(closed, str) and closed.startswith("Binary closed:"),
                                "Close failed",
                            )
                            inventory = await tools.call("bn_open_item_list")
                            require(
                                inventory.get("openItems") == [], "Inventory remains after close"
                            )
                            require(
                                await tools.call("list_binaries") == [], "Legacy inventory remains"
                            )
                            summary["closed_and_empty"] = True
                            summary["dual_output_responses"] = tools.dual_output_responses
            except Exception as error:
                summary["passed"] = False
                summary["failure"] = failure_message(error)[:500]
            finally:
                host_pids.update(_runtime_host_pids(runtime))
                remaining = _wait_for_pids(host_pids, 3)
                if remaining:
                    _stop_test_hosts(remaining)
                summary["hosts_stopped"] = not _wait_for_pids(host_pids, 3)
                summary["forced_host_pids"] = sorted(remaining)
                summary["passed"] = summary["passed"] and summary["hosts_stopped"]
                if not summary["passed"]:
                    diagnostics.flush()
                    with (Path(workspace) / "stderr.log").open("rb") as stream:
                        stream.seek(max(0, os.fstat(stream.fileno()).st_size - 4096))
                        summary["stderr_tail"] = stream.read(4096).decode("utf-8", errors="replace")
    summary.update(temporary_runtime_removed=True, seconds=time.monotonic() - started)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--function", action="append", required=True, dest="functions")
    parser.add_argument("--python", default="python3.13")
    parser.add_argument(
        "--timeout", type=float, default=120, help="total protocol deadline in seconds"
    )
    parser.add_argument(
        "--extras", action="store_true", help="also check native HLIL and legacy decompilation"
    )
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 1800:
        parser.error("--timeout must be finite and in (0, 1800]")
    if not 1 <= len(args.functions) <= 8 or any(
        not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", value) for value in args.functions
    ):
        parser.error("pass one to eight exact hexadecimal --function addresses")
    args.functions = [hex(int(value, 16)) for value in args.functions]
    if len(set(args.functions)) != len(args.functions):
        parser.error("function addresses must be distinct")
    summary = asyncio.run(run(args))
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
