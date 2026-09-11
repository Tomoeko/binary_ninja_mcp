#!/usr/bin/env python3
"""Run multiple MCP clients against one shared headless Binary Ninja host."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


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


def _status_from_output(stdout: str) -> dict[str, object]:
    for line in stdout.splitlines():
        if line.startswith("status="):
            return json.loads(line.removeprefix("status="))
    raise RuntimeError(f"MCP smoke omitted its status summary: {stdout[-1000:]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default="python3.13")
    parser.add_argument("--instances", type=int, default=4)
    parser.add_argument(
        "--binary",
        action="append",
        dest="binaries",
        help=(
            "source binary copied to one private target per client, or repeat "
            "exactly once per instance to use distinct targets"
        ),
    )
    args = parser.parse_args()
    if args.instances < 2:
        parser.error("--instances must be at least 2")
    requested = args.binaries or [str(REPO_ROOT / "example/chal")]
    if len(requested) not in {1, args.instances}:
        parser.error("--binary must be passed once or exactly --instances times")

    failures: list[str] = []
    statuses: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="binary-ninja-mcp-shared-smoke-") as workspace:
        workspace_path = Path(workspace)
        runtime = workspace_path / "runtime"
        barrier = workspace_path / "barrier"
        barrier.mkdir()
        if len(requested) == 1:
            source = Path(requested[0]).resolve()
            if not source.is_file():
                parser.error(f"binary does not exist: {source}")
            target_directory = workspace_path / "targets"
            target_directory.mkdir()
            binaries = []
            for index in range(1, args.instances + 1):
                target = target_directory / f"client-{index}-{source.name}"
                shutil.copy2(source, target)
                binaries.append(str(target.resolve()))
        else:
            binaries = [str(Path(binary).resolve()) for binary in requested]
            if len(set(binaries)) != args.instances:
                parser.error("each repeated --binary path must be distinct")
            missing = [binary for binary in binaries if not Path(binary).is_file()]
            if missing:
                parser.error(f"binary does not exist: {missing[0]}")

        processes: list[subprocess.Popen[str]] = []
        try:
            for binary in binaries:
                command = [
                    sys.executable,
                    str(REPO_ROOT / "tests" / "smoke_headless_mcp.py"),
                    "--python",
                    args.python,
                    "--binary",
                    binary,
                    "--shared-runtime-root",
                    str(runtime),
                    "--concurrency-barrier",
                    str(barrier),
                    "--barrier-participants",
                    str(args.instances),
                ]
                processes.append(
                    subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                )

            def communicate(
                index: int,
                binary: str,
                process: subprocess.Popen[str],
            ) -> tuple[int, str, subprocess.Popen[str], str, str, bool]:
                try:
                    stdout, stderr = process.communicate(timeout=120)
                    return index, binary, process, stdout, stderr, False
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
                    return index, binary, process, stdout, stderr, True

            with concurrent.futures.ThreadPoolExecutor(max_workers=args.instances) as executor:
                futures = [
                    executor.submit(communicate, index, binary, process)
                    for index, (binary, process) in enumerate(
                        zip(binaries, processes),
                        start=1,
                    )
                ]
                aborting = False
                for future in concurrent.futures.as_completed(futures):
                    index, binary, process, stdout, stderr, timed_out = future.result()
                    if timed_out:
                        failures.append(f"client {index} timed out\n{stderr[-3000:]}")
                    elif process.returncode != 0:
                        failures.append(
                            f"client {index} exited {process.returncode}\n"
                            f"stdout:\n{stdout[-1000:]}\nstderr:\n{stderr[-3000:]}"
                        )
                    else:
                        try:
                            status = _status_from_output(stdout)
                        except (RuntimeError, json.JSONDecodeError) as exc:
                            failures.append(f"client {index} status parse failed: {exc}")
                        else:
                            reported_filename = status.get("filename")
                            if not isinstance(reported_filename, str) or (
                                os.path.realpath(reported_filename) != os.path.realpath(binary)
                            ):
                                failures.append(
                                    f"client {index} target leaked: expected {binary}, "
                                    f"got {reported_filename!r}"
                                )
                            else:
                                instance_id = status.get("instance_id")
                                if not isinstance(instance_id, str) or not instance_id:
                                    failures.append(f"client {index} returned no host instance id")
                                else:
                                    statuses.append(status)
                                    print(
                                        f"client={index} binary={binary} "
                                        f"instance={instance_id} responses=ok"
                                    )
                    if failures and not aborting:
                        aborting = True
                        for pending_process in processes:
                            if pending_process.poll() is None:
                                pending_process.terminate()
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)

        host_pids = {
            int(status["pid"])
            for status in statuses
            if isinstance(status.get("pid"), int) and int(status["pid"]) > 0
        }
        host_pids.update(_runtime_host_pids(runtime))
        remaining_hosts = _wait_for_pids(host_pids, 8.0)
        if remaining_hosts:
            failures.append(
                f"shared test host did not stop after its final lease: {sorted(remaining_hosts)}"
            )
            _stop_test_hosts(remaining_hosts)

    if failures:
        raise RuntimeError("\n\n".join(failures))
    instance_ids = {str(status["instance_id"]) for status in statuses}
    if len(statuses) != args.instances or len(instance_ids) != 1:
        raise RuntimeError(
            "Concurrent MCP clients did not share exactly one host: "
            f"statuses={len(statuses)}, instance_ids={sorted(instance_ids)}"
        )
    required_capacity = len(set(binaries))
    capacities = {int(status.get("max_open_binaries", 0)) for status in statuses}
    if not capacities or min(capacities) < required_capacity:
        raise RuntimeError(
            "Shared host capacity is below the concurrent target count: "
            f"capacity={sorted(capacities)}, targets={required_capacity}"
        )
    print(
        f"concurrent_clients={args.instances} shared_instance={instance_ids.pop()} "
        f"capacity={min(capacities)} targets={required_capacity}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
