#!/usr/bin/env python3
"""Launch Binary Ninja headlessly and expose it as one stdio MCP server."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BN_PYTHON = Path(
    "/Applications/Binary Ninja.app/Contents/Resources/python"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="headless HTTP host")
    parser.add_argument("--port", type=int, default=9009, help="headless HTTP port")
    parser.add_argument(
        "--binary",
        action="append",
        default=[],
        metavar="PATH",
        help="binary to open at startup (repeatable)",
    )
    parser.add_argument(
        "--python",
        default=os.environ.get("BINJA_MCP_PYTHON", "python3.13"),
        help="Python interpreter used for Binary Ninja (default: python3.13)",
    )
    parser.add_argument(
        "--bn-python-path",
        default=os.environ.get("BINJA_PYTHON_PATH", str(DEFAULT_BN_PYTHON)),
        help="directory containing the binaryninja Python package",
    )
    parser.add_argument(
        "--bridge-python",
        default=os.environ.get("BINJA_MCP_BRIDGE_PYTHON"),
        help="Python with mcp and requests installed",
    )
    parser.add_argument(
        "--startup-timeout",
        type=float,
        default=30.0,
        help="seconds to wait for the headless HTTP service",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate only the Binary Ninja headless runtime",
    )
    return parser


def resolve_executable(value: str) -> str:
    candidate = Path(value).expanduser()
    if candidate.parent != Path("."):
        if candidate.is_file():
            return str(candidate.resolve())
        raise FileNotFoundError(f"Python interpreter does not exist: {candidate}")
    resolved = shutil.which(value)
    if not resolved:
        raise FileNotFoundError(f"Python interpreter is not on PATH: {value}")
    return resolved


def _can_run_bridge(interpreter: Path) -> bool:
    if not interpreter.is_file():
        return False
    result = subprocess.run(
        [
            str(interpreter),
            "-c",
            "import requests; "
            "import importlib.util; "
            "assert (importlib.util.find_spec('mcp.server.fastmcp') or "
            "importlib.util.find_spec('mcp.server.mcpserver'))",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def find_bridge_python(override: str | None) -> str:
    if override:
        candidate = Path(override).expanduser()
        if _can_run_bridge(candidate):
            # Do not resolve a virtualenv's python symlink: executing the target
            # directly drops the virtualenv's site-packages.
            return str(candidate.absolute())
        raise RuntimeError(
            f"Bridge Python cannot import mcp and requests: {candidate}"
        )

    candidates = [
        REPO_ROOT / ".venv" / "bin" / "python",
        Path.home()
        / "Library/Application Support/Binary Ninja/plugins/binary_ninja_mcp-main/.venv/bin/python",
        Path(sys.executable),
    ]
    for candidate in candidates:
        if _can_run_bridge(candidate):
            return str(candidate.absolute())
    raise RuntimeError(
        "No bridge Python can import mcp and requests. Create .venv and install "
        "bridge/requirements.txt, or set BINJA_MCP_BRIDGE_PYTHON."
    )


def host_environment(bn_python_path: Path) -> dict[str, str]:
    if not (bn_python_path / "binaryninja").is_dir():
        raise FileNotFoundError(
            f"binaryninja package not found below: {bn_python_path}"
        )
    env = os.environ.copy()
    current_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(bn_python_path) + (
        os.pathsep + current_pythonpath if current_pythonpath else ""
    )
    # Binary Ninja's macOS plugins reference libbinaryninjacore through @rpath.
    if sys.platform == "darwin":
        macos_dir = bn_python_path.parents[1] / "MacOS"
        current_dyld_path = env.get("DYLD_LIBRARY_PATH")
        env["DYLD_LIBRARY_PATH"] = str(macos_dir) + (
            os.pathsep + current_dyld_path if current_dyld_path else ""
        )
    env["BN_DISABLE_USER_PLUGINS"] = "1"
    env["BN_MCP_HEADLESS"] = "1"
    return env


def wait_for_host(
    process: subprocess.Popen,
    host: str,
    port: int,
    timeout: float,
    require_loaded: bool = False,
) -> None:
    deadline = time.monotonic() + timeout
    url = f"http://{host}:{port}/status"
    while time.monotonic() < deadline:
        return_code = process.poll()
        if return_code is not None:
            raise RuntimeError(
                f"Binary Ninja headless host exited during startup ({return_code})"
            )
        try:
            with urllib.request.urlopen(url, timeout=0.5) as response:
                status = json.load(response)
                if response.status == 200 and (
                    not require_loaded or bool(status.get("loaded"))
                ):
                    return
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(0.1)
    raise TimeoutError(f"Timed out waiting for Binary Ninja headless host at {url}")


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    host_python = resolve_executable(args.python)
    bn_python_path = Path(args.bn_python_path).expanduser().resolve()
    env = host_environment(bn_python_path)

    host_command = [
        host_python,
        str(REPO_ROOT / "bridge" / "headless_host.py"),
        "--host",
        args.host,
        "--port",
        str(args.port),
    ]
    for binary in args.binary:
        host_command.extend(["--binary", str(Path(binary).expanduser().resolve())])
    if args.check:
        host_command.append("--check")
        return subprocess.run(host_command, env=env, check=False).returncode

    bridge_python = find_bridge_python(args.bridge_python)
    host_process: subprocess.Popen | None = None
    bridge_process: subprocess.Popen | None = None
    try:
        # The host must never write to stdout because stdout carries MCP JSON-RPC.
        host_process = subprocess.Popen(
            host_command,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=sys.stderr,
            stderr=sys.stderr,
        )
        wait_for_host(
            host_process,
            args.host,
            args.port,
            args.startup_timeout,
            require_loaded=bool(args.binary),
        )

        bridge_env = os.environ.copy()
        bridge_env["BINJA_MCP_HOST"] = args.host
        bridge_env["BINJA_MCP_PORT"] = str(args.port)
        bridge_process = subprocess.Popen(
            [bridge_python, str(REPO_ROOT / "bridge" / "binja_mcp_bridge.py")],
            env=bridge_env,
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        return bridge_process.wait()
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"Headless Binary Ninja MCP startup failed: {exc}", file=sys.stderr)
        return 1
    finally:
        stop_process(bridge_process)
        stop_process(host_process)


if __name__ == "__main__":
    raise SystemExit(main())
