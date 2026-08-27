#!/usr/bin/env python3
"""Launch Binary Ninja headlessly and expose it as one stdio MCP server."""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BN_PYTHON = Path("/Applications/Binary Ninja.app/Contents/Resources/python")
# Local authenticated control traffic must never inherit HTTP_PROXY/ALL_PROXY.
# Besides breaking loopback startup, doing so could disclose the per-launch
# bearer token to an ambient proxy.
DIRECT_HTTP_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="headless HTTP host")
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="headless HTTP port (default: an isolated OS-assigned port)",
    )
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
        raise RuntimeError(f"Bridge Python cannot import mcp and requests: {candidate}")

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
        raise FileNotFoundError(f"binaryninja package not found below: {bn_python_path}")
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
    # Repository plugin discovery reads and rewrites one shared
    # ``channels/plugin_status.json``. Concurrent headless processes can race
    # there and initialize with only Raw/Mapped views, so disable a subsystem
    # that this native-analysis host never uses.
    env["BN_DISABLE_REPOSITORY_PLUGINS"] = "1"
    env["BN_MCP_HEADLESS"] = "1"
    return env


def default_binary_ninja_user_directory(
    environment: dict[str, str] | None = None,
) -> Path:
    environment = os.environ if environment is None else environment
    override = environment.get("BN_USER_DIRECTORY")
    if override:
        return Path(override).expanduser().resolve()
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/Binary Ninja"
    if sys.platform == "win32":
        appdata = environment.get("APPDATA")
        if appdata:
            return Path(appdata) / "Binary Ninja"
        return Path.home() / "AppData/Roaming/Binary Ninja"
    return Path.home() / ".binaryninja"


def prepare_isolated_user_directory(
    environment: dict[str, str],
    destination: Path,
    *,
    source: Path | None = None,
) -> None:
    """Give one headless host private writable Binary Ninja state.

    Binary Ninja's plugin manager rewrites ``channels/plugin_status.json``
    without a cross-process transaction. Keeping that state per launcher avoids
    corrupt native-plugin initialization while retaining the local license and
    settings needed by the headless runtime.
    """
    source = source or default_binary_ninja_user_directory(environment)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    # Keep the license out of crash-leftover temporary directories. Binary
    # Ninja officially accepts the full license through BN_LICENSE.
    license_file = source / "license.dat"
    if "BN_LICENSE" not in environment and license_file.is_file():
        environment["BN_LICENSE"] = license_file.read_text(encoding="utf-8")
    settings_file = source / "settings.json"
    if settings_file.is_file():
        shutil.copy2(settings_file, destination / "settings.json")
    environment["BN_USER_DIRECTORY"] = str(destination)


class HostEndpoint(NamedTuple):
    host: str
    port: int
    instance_id: str


def read_ready_file(
    ready_file: Path,
    *,
    expected_instance_id: str,
    expected_pid: int,
    expected_host: str,
) -> HostEndpoint | None:
    """Read and validate the private child readiness record.

    A missing or partially written record means startup is still in progress.
    A complete record with the wrong identity fails closed instead of allowing
    an unrelated process on the same port to impersonate the new host.
    """
    try:
        payload = json.loads(ready_file.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError, UnicodeError):
        return None
    if not isinstance(payload, dict):
        raise RuntimeError("Invalid Binary Ninja readiness record")
    if payload.get("protocol") != 1 or payload.get("event") != "ready":
        raise RuntimeError("Unsupported Binary Ninja readiness record")
    if payload.get("instance_id") != expected_instance_id:
        raise RuntimeError("Binary Ninja readiness instance identity mismatch")
    if payload.get("pid") != expected_pid:
        raise RuntimeError("Binary Ninja readiness child PID mismatch")
    if payload.get("host") != expected_host:
        raise RuntimeError("Binary Ninja readiness host mismatch")
    port = payload.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise RuntimeError("Binary Ninja readiness port is invalid")
    return HostEndpoint(expected_host, port, expected_instance_id)


def wait_for_host(
    process: subprocess.Popen,
    ready_file: Path,
    expected_instance_id: str,
    expected_host: str,
    auth_token: str,
    timeout: float,
    require_loaded: bool = False,
    target_binary: str | None = None,
) -> HostEndpoint:
    deadline = time.monotonic() + timeout
    endpoint: HostEndpoint | None = None
    last_url = "the private readiness endpoint"
    while time.monotonic() < deadline:
        return_code = process.poll()
        if return_code is not None:
            raise RuntimeError(f"Binary Ninja headless host exited during startup ({return_code})")
        if endpoint is None:
            endpoint = read_ready_file(
                ready_file,
                expected_instance_id=expected_instance_id,
                expected_pid=process.pid,
                expected_host=expected_host,
            )
            if endpoint is None:
                time.sleep(0.05)
                continue
        last_url = f"http://{endpoint.host}:{endpoint.port}/status"
        headers = {"X-Binary-Ninja-MCP-Token": auth_token}
        if target_binary:
            headers["X-Binary-Ninja-View-B64"] = base64.urlsafe_b64encode(
                target_binary.encode("utf-8")
            ).decode("ascii")
        request = urllib.request.Request(last_url, headers=headers)
        try:
            with DIRECT_HTTP_OPENER.open(request, timeout=0.5) as response:
                status = json.load(response)
                if status.get("instance_id") != expected_instance_id:
                    raise RuntimeError("Binary Ninja HTTP host instance identity mismatch")
                if response.status == 200 and (not require_loaded or bool(status.get("loaded"))):
                    return endpoint
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise RuntimeError("Binary Ninja HTTP host rejected its launcher token")
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(0.05)
    raise TimeoutError(f"Timed out waiting for Binary Ninja headless host at {last_url}")


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    # Headless hosts receive a private stdin pipe specifically so EOF can ask
    # for portable graceful shutdown (important on Windows, where terminate()
    # is an unconditional TerminateProcess). Bridges have no owned stdin pipe
    # and continue through the terminate/kill fallback below.
    stdin = getattr(process, "stdin", None)
    if stdin is not None and not getattr(stdin, "closed", False):
        try:
            stdin.close()
            process.wait(timeout=5)
            return
        except (BrokenPipeError, OSError, subprocess.TimeoutExpired):
            pass
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def supervise_processes(
    host_process: subprocess.Popen,
    bridge_process: subprocess.Popen,
    poll_interval: float = 0.1,
) -> int:
    """Return when either child exits and never leave a dead-host bridge alive."""
    while True:
        host_status = host_process.poll()
        bridge_status = bridge_process.poll()
        if host_status is not None:
            if bridge_status is None:
                print(
                    "Binary Ninja HTTP host exited while the MCP bridge was active "
                    f"(exit={host_status}); stopping the bridge.",
                    file=sys.stderr,
                )
                stop_process(bridge_process)
            return host_status if host_status != 0 else 1
        if bridge_status is not None:
            return bridge_status
        time.sleep(poll_interval)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    host_python = resolve_executable(args.python)
    bn_python_path = Path(args.bn_python_path).expanduser().resolve()
    with tempfile.TemporaryDirectory(prefix="binary-ninja-mcp-") as runtime_directory:
        runtime_path = Path(runtime_directory)
        env = host_environment(bn_python_path)
        prepare_isolated_user_directory(
            env,
            runtime_path / "binary-ninja-user",
        )
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
        instance_id = secrets.token_hex(16)
        auth_token = secrets.token_urlsafe(32)
        ready_file = runtime_path / "host-ready.json"
        host_command.extend(
            [
                "--ready-file",
                str(ready_file),
                "--exit-on-stdin-eof",
            ]
        )
        env["BINJA_MCP_INSTANCE_ID"] = instance_id
        env["BINJA_MCP_AUTH_TOKEN"] = auth_token
        try:
            # Host diagnostics stay on stderr. Its private stdin pipe is held by
            # this launcher and closes even if the launcher is killed abruptly.
            host_process = subprocess.Popen(
                host_command,
                env=env,
                stdin=subprocess.PIPE,
                stdout=sys.stderr,
                stderr=sys.stderr,
            )
            endpoint = wait_for_host(
                host_process,
                ready_file,
                instance_id,
                args.host,
                auth_token,
                args.startup_timeout,
                require_loaded=bool(args.binary),
                target_binary=(
                    str(Path(args.binary[0]).expanduser().resolve()) if args.binary else None
                ),
            )

            bridge_env = os.environ.copy()
            bridge_env["BINJA_MCP_HOST"] = endpoint.host
            bridge_env["BINJA_MCP_PORT"] = str(endpoint.port)
            bridge_env["BINJA_MCP_INSTANCE_ID"] = endpoint.instance_id
            bridge_env["BINJA_MCP_AUTH_TOKEN"] = auth_token
            bridge_env["BINJA_MCP_PARENT_PID"] = str(os.getpid())
            bridge_process = subprocess.Popen(
                [bridge_python, str(REPO_ROOT / "bridge" / "binja_mcp_bridge.py")],
                env=bridge_env,
                stdin=sys.stdin,
                stdout=sys.stdout,
                stderr=sys.stderr,
            )
            return supervise_processes(host_process, bridge_process)
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
