#!/usr/bin/env python3
"""Protocol-level smoke test for the headless Binary Ninja MCP launcher."""

from __future__ import annotations

import argparse
import json
import select
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default="python3.13")
    parser.add_argument("--binary", default=str(REPO_ROOT / "example/chal"))
    args = parser.parse_args()

    command = [
        args.python,
        str(REPO_ROOT / "scripts/run_headless_mcp.py"),
        "--binary",
        str(Path(args.binary).resolve()),
        "--startup-timeout",
        "30",
    ]
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": {"name": "headless-smoke", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "get_binary_status", "arguments": {}},
        },
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin and process.stdout and process.stderr

    responses = []
    for message in messages:
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()
        if "id" not in message:
            continue
        readable, _, _ = select.select([process.stdout], [], [], 45)
        if not readable:
            raise TimeoutError(f"Timed out waiting for MCP response {message['id']}")
        responses.append(json.loads(process.stdout.readline()))

    process.stdin.close()
    process.wait(timeout=15)
    stderr = process.stderr.read()
    by_id = {response.get("id"): response for response in responses if "id" in response}
    if process.returncode != 0 or not all(key in by_id for key in (1, 2, 3)):
        raise RuntimeError(
            f"MCP smoke test failed (exit={process.returncode})\n"
            f"responses={responses!r}\n{stderr[-3000:]}"
        )

    tools = by_id[2]["result"]["tools"]
    if not any(tool["name"] == "open_binary" for tool in tools):
        raise RuntimeError("open_binary was not advertised by tools/list")
    status = by_id[3]["result"]["content"][0]["text"]
    print(f"responses={sorted(by_id)}")
    print(f"tool_count={len(tools)}")
    print("open_binary=True")
    print(f"status={status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
