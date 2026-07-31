#!/usr/bin/env python3
"""Run the Binary Ninja HTTP service without starting the GUI."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind host")
    parser.add_argument("--port", type=int, default=9009, help="HTTP bind port")
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
    server = MCPServer(config)
    stopping = threading.Event()

    def request_stop(_signum=None, _frame=None) -> None:
        stopping.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    try:
        server.start()
        for path in args.binary:
            view = server.binary_ops.load_binary(path)
            print(
                f"Loaded {view.file.filename} ({len(list(view.functions))} functions)",
                file=sys.stderr,
                flush=True,
            )
        print(
            f"Binary Ninja headless HTTP service ready at http://{args.host}:{args.port}",
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
