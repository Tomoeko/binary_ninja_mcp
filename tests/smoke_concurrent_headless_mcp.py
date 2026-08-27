#!/usr/bin/env python3
"""Run independent default-port Binary Ninja MCP launchers concurrently."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default="python3.13")
    parser.add_argument("--instances", type=int, default=2)
    parser.add_argument("--binary", default=str(REPO_ROOT / "example/chal"))
    args = parser.parse_args()
    if args.instances < 2:
        parser.error("--instances must be at least 2")

    command = [
        sys.executable,
        str(REPO_ROOT / "tests" / "smoke_headless_mcp.py"),
        "--python",
        args.python,
        "--binary",
        str(Path(args.binary).resolve()),
    ]
    processes = [
        subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(args.instances)
    ]
    failures: list[str] = []
    try:
        for index, process in enumerate(processes, start=1):
            try:
                stdout, stderr = process.communicate(timeout=120)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                failures.append(f"instance {index} timed out\n{stderr[-3000:]}")
                continue
            if process.returncode != 0:
                failures.append(
                    f"instance {index} exited {process.returncode}\n"
                    f"stdout:\n{stdout[-1000:]}\nstderr:\n{stderr[-3000:]}"
                )
            else:
                print(f"instance={index} {stdout.strip().replace(chr(10), ' ')}")
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    if failures:
        raise RuntimeError("\n\n".join(failures))
    print(f"concurrent_instances={args.instances}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
