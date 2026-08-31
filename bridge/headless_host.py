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


def positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def current_rss_bytes() -> int | None:
    """Read current resident memory without requiring a third-party package."""
    if sys.platform.startswith("linux"):
        try:
            resident_pages = int(Path("/proc/self/statm").read_text().split()[1])
            return resident_pages * int(os.sysconf("SC_PAGE_SIZE"))
        except (OSError, ValueError, IndexError):
            pass
    elif sys.platform == "darwin":
        try:
            import ctypes

            class ProcTaskInfo(ctypes.Structure):
                _fields_ = [
                    ("virtual_size", ctypes.c_uint64),
                    ("resident_size", ctypes.c_uint64),
                    ("total_user", ctypes.c_uint64),
                    ("total_system", ctypes.c_uint64),
                    ("threads_user", ctypes.c_uint64),
                    ("threads_system", ctypes.c_uint64),
                    ("policy", ctypes.c_int32),
                    ("faults", ctypes.c_int32),
                    ("pageins", ctypes.c_int32),
                    ("cow_faults", ctypes.c_int32),
                    ("messages_sent", ctypes.c_uint32),
                    ("messages_received", ctypes.c_uint32),
                    ("syscalls_mach", ctypes.c_uint32),
                    ("syscalls_unix", ctypes.c_uint32),
                    ("context_switches", ctypes.c_int32),
                    ("thread_count", ctypes.c_int32),
                    ("running_threads", ctypes.c_int32),
                    ("priority", ctypes.c_int32),
                ]

            task_info = ProcTaskInfo()
            libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            libproc.proc_pidinfo.argtypes = [
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint64,
                ctypes.c_void_p,
                ctypes.c_int,
            ]
            libproc.proc_pidinfo.restype = ctypes.c_int
            written = libproc.proc_pidinfo(
                os.getpid(),
                4,  # PROC_PIDTASKINFO
                0,
                ctypes.byref(task_info),
                ctypes.sizeof(task_info),
            )
            if written == ctypes.sizeof(task_info):
                return int(task_info.resident_size)
        except (OSError, ValueError):
            pass
    elif sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class ProcessMemoryCounters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("page_fault_count", wintypes.DWORD),
                    ("peak_working_set_size", ctypes.c_size_t),
                    ("working_set_size", ctypes.c_size_t),
                    ("quota_peak_paged_pool_usage", ctypes.c_size_t),
                    ("quota_paged_pool_usage", ctypes.c_size_t),
                    ("quota_peak_nonpaged_pool_usage", ctypes.c_size_t),
                    ("quota_nonpaged_pool_usage", ctypes.c_size_t),
                    ("pagefile_usage", ctypes.c_size_t),
                    ("peak_pagefile_usage", ctypes.c_size_t),
                ]

            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            get_current_process = ctypes.windll.kernel32.GetCurrentProcess
            get_current_process.argtypes = []
            get_current_process.restype = wintypes.HANDLE
            get_process_memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
            get_process_memory_info.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(ProcessMemoryCounters),
                wintypes.DWORD,
            ]
            get_process_memory_info.restype = wintypes.BOOL
            if get_process_memory_info(
                get_current_process(),
                ctypes.byref(counters),
                counters.cb,
            ):
                return int(counters.working_set_size)
        except (AttributeError, OSError, ValueError):
            pass
    try:
        import resource

        peak = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        return peak if sys.platform == "darwin" else peak * 1024
    except (ImportError, OSError, ValueError):
        return None


def monitor_memory_limit(
    stopping,
    server,
    max_rss_bytes: int,
    emergency_checkpoint=None,
) -> None:
    """Fail-stop a host generation before native analysis exhausts memory."""
    while not stopping.wait(0.25):
        rss = current_rss_bytes()
        if rss is None or rss <= max_rss_bytes:
            continue
        # Make recovery forget every heavyweight view before waiting for the
        # Binary Ninja operation lock. A native request can hold that lock for
        # minutes; journaling first prevents a forced-exit/recovery loop from
        # reopening the same over-limit inputs.
        if emergency_checkpoint is not None and emergency_checkpoint() is False:
            # A shared child can observe its baseline RSS before the parent has
            # published the pending generation record. Retry on the next poll;
            # clearing a prior generation's manifest would be unsafe.
            continue
        try:
            import binaryninja as bn

            bn.log_error(
                "Binary Ninja MCP resident-memory limit exceeded "
                f"({rss / (1024**3):.2f} GiB > {max_rss_bytes / (1024**3):.2f} GiB); "
                "closing managed views and recycling the headless host"
            )
        except Exception:
            pass
        stopping.set()
        # Binary Ninja can be inside a long native request while the HTTP
        # server and operation lock wait. A bounded fail-safe guarantees the
        # over-limit process cannot continue toward system-wide exhaustion if
        # cooperative analysis cancellation or disposal wedges.
        force_exit = threading.Timer(10.0, os._exit, args=(137,))
        force_exit.daemon = True
        force_exit.start()
        try:
            with server.operation_lock:
                # An emergency process recycle must release every native view,
                # including modified transient views, and persist an empty
                # recovery inventory so they are not reopened in a loop.
                server.binary_ops.close_owned_views(persist_inventory=False)
        finally:
            force_exit.cancel()
        return


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
        "--max-open-binaries",
        type=positive_integer,
        default=os.environ.get("BINJA_MCP_MAX_OPEN_BINARIES", "2"),
        help=(
            "maximum headless BinaryViews retained at once "
            "(default: 2; override with BINJA_MCP_MAX_OPEN_BINARIES)"
        ),
    )
    parser.add_argument(
        "--max-rss-mb",
        type=positive_integer,
        default=os.environ.get("BINJA_MCP_MAX_RSS_MB", "16384"),
        help=(
            "resident-memory ceiling in MiB before managed views are closed "
            "and the headless host is recycled (default: 16384)"
        ),
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
        raise RuntimeError("--lease-directory and --shared-state-file must be supplied together")
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
    config.binary_ninja.max_owned_views = args.max_open_binaries
    config.binary_ninja.max_rss_mb = args.max_rss_mb
    instance_id = os.environ.get("BINJA_MCP_INSTANCE_ID") or uuid.uuid4().hex
    auth_token = os.environ.get("BINJA_MCP_AUTH_TOKEN") or None
    shared_runtime = SharedHostRuntime.from_environment()
    inventory_gate = threading.Lock()
    emergency_recycle = threading.Event()
    journal_watermark = [1]

    def journal_owned_binaries(
        records: list[dict[str, object]],
        next_view_id: int,
    ) -> None:
        with inventory_gate:
            journal_watermark[0] = max(journal_watermark[0], next_view_id)
            if shared_runtime is None:
                return
            try:
                shared_runtime.replace_binary_session_for_instance(
                    instance_id,
                    [] if emergency_recycle.is_set() else records,
                    journal_watermark[0],
                )
            except Exception:
                # Native close and filesystem replacement cannot be one
                # transaction. Fail-stop this generation rather than continue
                # with a cache that disagrees with recovery state.
                stopping.set()
                raise

    def checkpoint_emergency_recycle() -> bool:
        # This gate is deliberately independent of Binary Ninja's operation
        # lock. Once set, later in-flight inventory callbacks may advance the
        # selector watermark but can only persist an empty resident set.
        with inventory_gate:
            if shared_runtime is None:
                emergency_recycle.set()
                return True
            current = shared_runtime.current_record(require_ready=False)
            if current is None:
                return False
            if current.endpoint.instance_id == instance_id:
                shared_runtime.replace_binary_session_for_instance(
                    instance_id, [], journal_watermark[0]
                )
            # A superseded host must stop, but must not alter its successor's
            # recovery manifest.
            emergency_recycle.set()
            return True

    server = MCPServer(
        config,
        instance_id=instance_id,
        auth_token=auth_token,
        binary_inventory_callback=(journal_owned_binaries if shared_runtime is not None else None),
        rss_provider=current_rss_bytes,
    )

    try:
        if stopping.is_set():
            return 0
        _bound_host, bound_port = server.start()
        threading.Thread(
            target=monitor_memory_limit,
            args=(
                stopping,
                server,
                args.max_rss_mb * 1024 * 1024,
                checkpoint_emergency_recycle,
            ),
            daemon=True,
            name="binary-ninja-mcp-memory-limit",
        ).start()
        for path in args.binary:
            if stopping.is_set():
                break
            view = server.binary_ops.load_binary(path)
            opened_filename = view.file.filename
            print(
                f"Opened {opened_filename}; background analysis started",
                file=sys.stderr,
                flush=True,
            )
            # Do not let the startup-loop local outlive the service-owned LRU
            # reference; eviction must be able to dispose the wrapper fully.
            del view
        if stopping.is_set():
            return 0
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
