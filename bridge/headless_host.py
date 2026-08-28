#!/usr/bin/env python3
"""Run the Binary Ninja HTTP service without starting the GUI."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from shared_host import SharedHostRuntime, monitor_shared_host_lifetime  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind host")
    parser.add_argument("--port", type=int, default=9009, help="HTTP bind port")
    parser.add_argument(
        "--ready-file",
        help="private launcher-owned path for the bound endpoint handshake",
    )
    parser.add_argument(
        "--exit-on-stdin-eof",
        action="store_true",
        help="stop when the launcher closes the private stdin liveness pipe",
    )
    parser.add_argument(
        "--lease-directory",
        help="private shared-host directory containing locked client leases",
    )
    parser.add_argument(
        "--shared-state-file",
        help="private registry record used to detect host supersession",
    )
    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=60.0,
        help="seconds to retain a shared host after its final client exits",
    )
    parser.add_argument(
        "--claim-timeout",
        type=float,
        default=30.0,
        help="seconds a new shared host waits to be published in the registry",
    )
    parser.add_argument(
        "--binary",
        action="append",
        default=[],
        metavar="PATH",
        help="binary to open at startup (repeatable)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the Binary Ninja headless runtime and exit",
    )
    return parser


def publish_ready_file(path: str, payload: dict[str, object]) -> None:
    """Publish one readiness record without overwriting any existing path."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        encoded = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def stop_on_stdin_eof(
    stopping: threading.Event,
    descriptor: int,
) -> None:
    """Use a private pipe as a portable parent-death signal."""
    try:
        while not stopping.is_set():
            # Use the unbuffered descriptor so a blocked daemon reader cannot
            # hold ``sys.stdin``'s buffered lock during interpreter shutdown.
            if not os.read(descriptor, 1):
                stopping.set()
                return
    except (OSError, ValueError):
        stopping.set()


def validate_runtime(bn) -> tuple[list[str], list[str], list[str]]:
    """Initialize native plugins and reject a raw-only analysis runtime."""
    bn._init_plugins()
    architectures = [architecture.name for architecture in bn.Architecture]
    platforms = [platform.name for platform in bn.Platform]
    view_types = [view_type.name for view_type in bn.BinaryViewType]
    usable_views = [name for name in view_types if name not in {"Raw", "Mapped"}]
    if not architectures or not platforms or not usable_views:
        raise RuntimeError(
            "Binary Ninja imported, but its native analysis plugins did not initialize "
            f"(architectures={len(architectures)}, platforms={len(platforms)}, "
            f"view_types={view_types}). "
            "Headless analysis would only produce a raw/mapped view with no functions."
        )
    return architectures, platforms, view_types


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if bool(args.lease_directory) != bool(args.shared_state_file):
        raise RuntimeError(
            "--lease-directory and --shared-state-file must be supplied together"
        )
    if args.idle_timeout <= 0 or args.claim_timeout <= 0:
        raise RuntimeError("--idle-timeout and --claim-timeout must be positive")

    stopping = threading.Event()

    def request_stop(_signum=None, _frame=None) -> None:
        stopping.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    if args.exit_on_stdin_eof:
        stdin_thread = threading.Thread(
            target=stop_on_stdin_eof,
            args=(stopping, sys.stdin.fileno()),
            daemon=True,
            name="binary-ninja-mcp-parent-watch",
        )
        stdin_thread.start()

    # A headless service should not recursively load the GUI copy of this plugin.
    os.environ.setdefault("BN_DISABLE_USER_PLUGINS", "1")
    sys.path.insert(0, str(REPO_ROOT))

    try:
        import binaryninja as bn

        try:
            bn.log_to_stderr(bn.LogLevel.InfoLog)
        except Exception:
            pass
        architectures, platforms, view_types = validate_runtime(bn)
    except Exception as exc:
        print(f"Binary Ninja headless runtime check failed: {exc}", file=sys.stderr)
        return 2

    print(
        "Binary Ninja headless runtime ready: "
        f"{len(architectures)} architectures, {len(platforms)} platforms, "
        f"{len(view_types)} view types",
        file=sys.stderr,
        flush=True,
    )
    if args.check:
        return 0

    from plugin.core.config import Config
    from plugin.server.http_server import MCPServer

    config = Config()
    config.server.host = args.host
    config.server.port = args.port
    instance_id = os.environ.get("BINJA_MCP_INSTANCE_ID") or uuid.uuid4().hex
    auth_token = os.environ.get("BINJA_MCP_AUTH_TOKEN") or None
    shared_runtime = SharedHostRuntime.from_environment()

    def journal_loaded_binary(payload: dict[str, object], view_id: str | int) -> None:
        if shared_runtime is not None:
            shared_runtime.remember_binary_for_instance(instance_id, payload, view_id)

    server = MCPServer(
        config,
        instance_id=instance_id,
        auth_token=auth_token,
        binary_loaded_callback=journal_loaded_binary if shared_runtime is not None else None,
    )

    try:
        if stopping.is_set():
            return 0
        _bound_host, bound_port = server.start()
        for path in args.binary:
            view = server.binary_ops.load_binary(path)
            print(
                f"Opened {view.file.filename}; background analysis started",
                file=sys.stderr,
                flush=True,
            )
        if args.ready_file:
            publish_ready_file(
                args.ready_file,
                {
                    "protocol": 1,
                    "event": "ready",
                    "instance_id": instance_id,
                    "pid": os.getpid(),
                    "host": args.host,
                    "port": bound_port,
                },
            )
        if args.lease_directory and args.shared_state_file:
            threading.Thread(
                target=monitor_shared_host_lifetime,
                args=(
                    stopping,
                    Path(args.lease_directory),
                    Path(args.shared_state_file),
                    instance_id,
                    args.idle_timeout,
                    args.claim_timeout,
                ),
                daemon=True,
                name="binary-ninja-mcp-shared-lifetime",
            ).start()
        print(
            f"Binary Ninja headless HTTP service ready at http://{args.host}:{bound_port}",
            file=sys.stderr,
            flush=True,
        )
        stopping.wait()
        return 0
    except Exception as exc:
        print(f"Binary Ninja headless host failed: {exc}", file=sys.stderr)
        return 1
    finally:
        server.stop()
        server.binary_ops.close_owned_views()


if __name__ == "__main__":
    raise SystemExit(main())
