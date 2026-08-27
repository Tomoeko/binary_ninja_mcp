"""Losslessly update the Binary Ninja entry in Codex's TOML configuration."""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from collections.abc import Callable, MutableMapping, Sequence
from pathlib import Path

import tomlkit
from tomlkit.items import InlineTable

SERVER_NAME = "binary_ninja"
MINIMUM_STARTUP_TIMEOUT_SEC = 45
MINIMUM_TOOL_TIMEOUT_SEC = 1800
_HTTP_TRANSPORT_FIELDS = frozenset(
    {
        "url",
        "bearer_token",
        "bearer_token_env_var",
        "http_headers",
        "env_http_headers",
        "http_headers_helper",
        "auth",
        "oauth",
        "oauth_resource",
    }
)
_OWNED_FIELDS = _HTTP_TRANSPORT_FIELDS | {
    "command",
    "args",
    "startup_timeout_sec",
    "tool_timeout_sec",
}


def _plain_document(document) -> dict:
    value = document.unwrap()
    if not isinstance(value, dict):
        raise RuntimeError("Codex configuration root is not a TOML table")
    return value


def _server_value(document) -> dict | None:
    root = _plain_document(document)
    servers = root.get("mcp_servers")
    if servers is None:
        return None
    if not isinstance(servers, dict):
        raise RuntimeError("Codex mcp_servers value is not a TOML table")
    server = servers.get(SERVER_NAME)
    if server is None:
        return None
    if not isinstance(server, dict):
        raise RuntimeError(f"Codex MCP entry {SERVER_NAME!r} is not a TOML table")
    return server


def _unowned_server_values(document) -> dict:
    server = _server_value(document) or {}
    return {key: value for key, value in server.items() if key not in _OWNED_FIELDS}


def _valid_timeout(value: object, minimum: int) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= minimum
    )


def _entry_is_current(server: dict | None, command: str, args: list[str]) -> bool:
    if server is None:
        return False
    return (
        server.get("command") == command
        and server.get("args") == args
        and _valid_timeout(server.get("startup_timeout_sec"), MINIMUM_STARTUP_TIMEOUT_SEC)
        and _valid_timeout(server.get("tool_timeout_sec"), MINIMUM_TOOL_TIMEOUT_SEC)
        and not _HTTP_TRANSPORT_FIELDS.intersection(server)
    )


def _editable_server(document) -> MutableMapping:
    servers = document.get("mcp_servers")
    if servers is None:
        servers = tomlkit.table()
        document["mcp_servers"] = servers
    if not isinstance(servers, MutableMapping):
        raise RuntimeError("Codex mcp_servers value is not an editable TOML table")

    server = servers.get(SERVER_NAME)
    if server is None:
        server = tomlkit.inline_table() if isinstance(servers, InlineTable) else tomlkit.table()
        servers[SERVER_NAME] = server
    if not isinstance(server, MutableMapping):
        raise RuntimeError(f"Codex MCP entry {SERVER_NAME!r} is not an editable TOML table")
    return server


def _preserve_newline_style(source: str, updated: str) -> str:
    """Use CRLF for inserted lines when the original file was uniformly CRLF."""
    if "\r\n" in source and "\n" not in source.replace("\r\n", ""):
        return updated.replace("\r\n", "\n").replace("\n", "\r\n")
    return updated


def _resolve_config_target(config_path: Path) -> Path:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if config_path.is_symlink():
        try:
            target = config_path.resolve(strict=True)
        except FileNotFoundError as exc:
            raise RuntimeError(f"Refusing dangling Codex config symlink: {config_path}") from exc
        if not target.is_file():
            raise RuntimeError(f"Codex config symlink target is not a file: {target}")
        return target

    target = config_path.resolve(strict=False)
    if target.exists() and not target.is_file():
        raise RuntimeError(f"Codex config path is not a file: {target}")
    return target


@contextlib.contextmanager
def _config_lock(target: Path):
    """Serialize cooperating editors across processes using a stable lock file."""
    lock_path = target.parent / ".binary-ninja-mcp-config.lock"
    with lock_path.open("a+b") as lock_file:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0, os.SEEK_END)
            if lock_file.tell() == 0:
                lock_file.write(b"\0")
                lock_file.flush()
            deadline = time.monotonic() + 90
            while True:
                lock_file.seek(0)
                try:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError as exc:
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            f"Timed out waiting for Codex config lock: {lock_path}"
                        ) from exc
                    time.sleep(0.1)
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _assert_config_unchanged(target: Path, original: bytes, existed: bool) -> None:
    if existed:
        try:
            current = target.read_bytes()
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"Codex config changed while it was being updated: {target}"
            ) from exc
        if current != original:
            raise RuntimeError(
                f"Codex config changed concurrently; refusing to overwrite: {target}"
            )
    elif target.exists():
        raise RuntimeError(f"Codex config appeared concurrently; refusing to overwrite: {target}")


def _copy_security_metadata(source: Path, destination: Path) -> None:
    """Populate a replacement inode while retaining platform security metadata."""
    copy = shutil.which("cp")
    if not copy:
        raise RuntimeError(
            "Cannot safely replace an existing Codex config: metadata-preserving cp is unavailable"
        )
    command = [copy]
    if sys.platform.startswith("linux"):
        command.append("--preserve=all")
    else:
        command.append("-p")
    command.extend([str(source), str(destination)])
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        error = result.stderr.strip() or "metadata copy failed"
        raise RuntimeError(f"Cannot preserve Codex config security metadata: {error}")

    source_stat = source.stat()
    destination_stat = destination.stat()
    for attribute in ("st_uid", "st_gid"):
        if hasattr(source_stat, attribute) and getattr(source_stat, attribute) != getattr(
            destination_stat, attribute
        ):
            raise RuntimeError(
                f"Cannot preserve Codex config {attribute.removeprefix('st_')}: {source}"
            )
    if stat.S_IMODE(source_stat.st_mode) != stat.S_IMODE(destination_stat.st_mode):
        raise RuntimeError(f"Cannot preserve Codex config permissions: {source}")


def _replace_in_place(target: Path, original: bytes, updated: bytes) -> None:
    """Windows fallback that retains the destination inode and its DACL."""
    _assert_config_unchanged(target, original, True)
    try:
        with target.open("r+b") as config_file:
            config_file.seek(0)
            config_file.write(updated)
            config_file.truncate()
            config_file.flush()
            os.fsync(config_file.fileno())
    except BaseException:
        # Restore on ordinary write failures. A process-level crash can still
        # interrupt this Windows-only fallback, but never substitutes an inode
        # with a different security descriptor.
        try:
            with target.open("r+b") as config_file:
                config_file.seek(0)
                config_file.write(original)
                config_file.truncate()
                config_file.flush()
                os.fsync(config_file.fileno())
        finally:
            raise


def _atomic_replace(target: Path, original: bytes, updated: bytes, existed: bool) -> None:
    _assert_config_unchanged(target, original, existed)
    if existed:
        target_stat = target.stat()
        if target_stat.st_nlink != 1:
            raise RuntimeError(
                f"Refusing to replace hard-linked Codex config ({target_stat.st_nlink} links): "
                f"{target}"
            )
        if os.name == "nt":
            _replace_in_place(target, original, updated)
            return
        mode = stat.S_IMODE(target_stat.st_mode)
    else:
        mode = 0o600

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".binary-ninja-mcp-",
        suffix=".toml",
        dir=target.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        os.close(descriptor)
        if existed:
            _copy_security_metadata(target, temporary_path)
        with temporary_path.open("r+b" if existed else "wb") as temporary_file:
            temporary_file.seek(0)
            temporary_file.write(updated)
            temporary_file.truncate()
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.chmod(temporary_path, mode)
        # Recheck after the potentially slow write/fsync so a non-cooperating
        # config writer is not silently overwritten in the common race window.
        _assert_config_unchanged(target, original, existed)
        os.replace(temporary_path, target)
        try:
            directory_descriptor = os.open(target.parent, os.O_RDONLY)
        except OSError:
            directory_descriptor = None
        if directory_descriptor is not None:
            try:
                os.fsync(directory_descriptor)
            except OSError:
                pass
            finally:
                os.close(directory_descriptor)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def update_codex_mcp_entry(
    config_path: str | os.PathLike[str],
    command: str,
    args: Sequence[str],
    validator: Callable[[bytes], None] | None = None,
) -> bool:
    """Update only this repository's paths and minimum wait budgets.

    Existing approval policy, environment, enablement, tool filters, custom
    fields, comments, and table spelling are left under the user's control.
    Returns ``True`` only when the configuration bytes were changed.
    """
    if not command:
        raise ValueError("command must not be empty")
    normalized_args = list(args)
    if not all(isinstance(value, str) for value in normalized_args):
        raise TypeError("all command arguments must be strings")

    logical_path = Path(config_path).expanduser().absolute()
    target = _resolve_config_target(logical_path)
    with _config_lock(target):
        return _update_locked(target, command, normalized_args, validator)


def _update_locked(
    target: Path,
    command: str,
    normalized_args: list[str],
    validator: Callable[[bytes], None] | None,
) -> bool:
    """Perform one update while the stable per-config lock is held."""
    existed = target.exists()
    original = target.read_bytes() if existed else b""
    try:
        source = original.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"Codex config is not valid UTF-8: {target}") from exc

    try:
        document = tomlkit.parse(source) if source.strip() else tomlkit.document()
    except Exception as exc:
        raise RuntimeError(f"Codex config is not valid TOML: {target}: {exc}") from exc

    before_unowned = _unowned_server_values(document)
    before_server = _server_value(document)
    if _entry_is_current(before_server, command, normalized_args):
        return False

    server = _editable_server(document)
    # Codex selects the stdio transport when command is present and rejects any
    # HTTP/SSE-only fields alongside it. Remove fields owned by the superseded
    # transport while retaining all settings valid for stdio.
    for field in _HTTP_TRANSPORT_FIELDS:
        server.pop(field, None)
    server["command"] = command
    server["args"] = normalized_args
    if not _valid_timeout(server.get("startup_timeout_sec"), MINIMUM_STARTUP_TIMEOUT_SEC):
        server["startup_timeout_sec"] = MINIMUM_STARTUP_TIMEOUT_SEC
    if not _valid_timeout(server.get("tool_timeout_sec"), MINIMUM_TOOL_TIMEOUT_SEC):
        server["tool_timeout_sec"] = MINIMUM_TOOL_TIMEOUT_SEC

    updated_source = _preserve_newline_style(source, tomlkit.dumps(document))
    try:
        validated = tomlkit.parse(updated_source)
        # Also validate against the standard-library TOML 1.0 parser used by
        # the rest of the installer tests.
        tomllib.loads(updated_source)
    except Exception as exc:
        raise RuntimeError(f"Generated Codex config is not valid TOML: {exc}") from exc

    after_server = _server_value(validated)
    if not _entry_is_current(after_server, command, normalized_args):
        raise RuntimeError("Generated Codex MCP entry failed postcondition validation")
    if _unowned_server_values(validated) != before_unowned:
        raise RuntimeError("Generated Codex MCP entry changed an unowned setting")

    updated = updated_source.encode("utf-8")
    if updated == original:
        return False
    if validator is not None:
        validator(updated)
    _atomic_replace(target, original, updated, existed)
    return True


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--args-json", required=True)
    parser.add_argument(
        "--codex-cli",
        help="Validate the candidate with this Codex executable before replacing config.toml",
    )
    return parser


def _codex_validator(codex_cli: str) -> Callable[[bytes], None]:
    executable = str(Path(codex_cli).expanduser().absolute())

    def validate(candidate: bytes) -> None:
        with tempfile.TemporaryDirectory(prefix="binary-ninja-mcp-codex-check-") as directory:
            candidate_path = Path(directory) / "config.toml"
            candidate_path.write_bytes(candidate)
            candidate_path.chmod(0o600)
            environment = os.environ.copy()
            environment["CODEX_HOME"] = directory
            result = subprocess.run(
                [executable, "mcp", "get", SERVER_NAME],
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        if result.returncode != 0:
            error = result.stderr.strip() or "Codex rejected the generated MCP entry"
            raise RuntimeError(f"Generated Codex MCP entry failed schema validation: {error}")

    return validate


def main() -> int:
    options = _parser().parse_args()
    args = json.loads(options.args_json)
    if not isinstance(args, list) or not all(isinstance(value, str) for value in args):
        raise ValueError("--args-json must contain an array of strings")
    validator = _codex_validator(options.codex_cli) if options.codex_cli else None
    changed = update_codex_mcp_entry(options.config, options.command, args, validator)
    print("updated" if changed else "already-current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
