#!/usr/bin/env python3
"""Coordinate one lazy headless Binary Ninja host across MCP stdio clients.

The MCP client starts one stdio server per task.  Starting Binary Ninja in each
of those processes is both unnecessary and expensive, so launchers hold a
small advisory-lock lease while bridges discover or create one authenticated
loopback HTTP host through this private registry.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import http.client
import json
import math
import os
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BN_PYTHON = Path("/Applications/Binary Ninja.app/Contents/Resources/python")
REGISTRY_PROTOCOL = 1
HEALTH_PROTOCOL = 1
DEFAULT_IDLE_TIMEOUT_SEC = 60.0
DEFAULT_RECOVERY_TIMEOUT_SEC = 30.0
CONFIG_ENV = "BINJA_MCP_SHARED_HOST_CONFIG"
DIRECT_HTTP_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class HostEndpoint(NamedTuple):
    host: str
    port: int
    instance_id: str


class HostRecord(NamedTuple):
    endpoint: HostEndpoint
    pid: int
    auth_token: str
    fingerprint: str
    ready: bool


class HostConnectionLost(RuntimeError):
    """The host connection closed before a response was received."""


class HostResponseTimedOut(RuntimeError):
    """The host stayed connected but did not answer within the finite budget."""


class SessionRestoreError(RuntimeError):
    """Recovery cannot preserve the prior stable view-id mapping."""


def _positive_number(value: object, name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{name} must be a positive number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise RuntimeError(f"{name} must be a positive finite number")
    return parsed


def _source_fingerprint(
    host_python: str,
    bn_python_path: Path,
    bind_host: str,
    bind_port: int,
) -> str:
    """Name hosts by runtime and all Python source loaded into the native host."""
    digest = hashlib.sha256()
    for value in (
        str(REGISTRY_PROTOCOL),
        str(Path(host_python).absolute()),
        str(bn_python_path.resolve()),
        bind_host,
        str(bind_port),
    ):
        digest.update(value.encode("utf-8"))
        digest.update(b"\0")
    sources = [
        REPO_ROOT / "bridge" / "binja_mcp_bridge.py",
        REPO_ROOT / "bridge" / "headless_host.py",
        REPO_ROOT / "bridge" / "shared_host.py",
    ]
    sources.extend(sorted((REPO_ROOT / "plugin").rglob("*.py")))
    for source in sources:
        digest.update(str(source.relative_to(REPO_ROOT)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(source.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _default_runtime_root() -> Path:
    override = os.environ.get("BINJA_MCP_SHARED_RUNTIME_ROOT", "").strip()
    if override:
        return Path(override).expanduser().absolute()
    return Path(tempfile.gettempdir()) / f"binary-ninja-mcp-{_user_identity()}"


def _user_identity() -> str:
    getuid = getattr(os, "getuid", None)
    if callable(getuid):
        return str(getuid())
    return os.environ.get("USERNAME") or os.environ.get("USER") or "user"


@dataclass(frozen=True)
class SharedHostConfig:
    host_python: str
    bn_python_path: Path
    bind_host: str
    bind_port: int
    startup_timeout: float
    idle_timeout: float
    recovery_timeout: float
    fingerprint: str
    runtime_directory: Path
    startup_binaries: tuple[str, ...] = ()

    @property
    def state_file(self) -> Path:
        return self.runtime_directory / "host.json"

    @property
    def state_lock_file(self) -> Path:
        return self.runtime_directory / "host.lock"

    @property
    def session_file(self) -> Path:
        return self.runtime_directory / "binaries.json"

    @property
    def session_lock_file(self) -> Path:
        return self.runtime_directory / "binaries.lock"

    @property
    def lease_directory(self) -> Path:
        return self.runtime_directory / "clients"

    @property
    def lease_lock_file(self) -> Path:
        return self.runtime_directory / "clients.lock"

    @property
    def log_file(self) -> Path:
        return self.runtime_directory / "host.log"

    def to_environment(self, environment: dict[str, str]) -> None:
        environment[CONFIG_ENV] = json.dumps(
            {
                "protocol": REGISTRY_PROTOCOL,
                "host_python": self.host_python,
                "bn_python_path": str(self.bn_python_path),
                "bind_host": self.bind_host,
                "bind_port": self.bind_port,
                "startup_timeout": self.startup_timeout,
                "idle_timeout": self.idle_timeout,
                "recovery_timeout": self.recovery_timeout,
                "fingerprint": self.fingerprint,
                "runtime_directory": str(self.runtime_directory),
                "startup_binaries": list(self.startup_binaries),
            },
            separators=(",", ":"),
        )

    @classmethod
    def from_environment(cls) -> SharedHostConfig | None:
        encoded = os.environ.get(CONFIG_ENV, "").strip()
        if not encoded:
            return None
        try:
            data = json.loads(encoded)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"{CONFIG_ENV} is not valid JSON") from exc
        if not isinstance(data, dict) or data.get("protocol") != REGISTRY_PROTOCOL:
            raise RuntimeError(f"{CONFIG_ENV} uses an unsupported protocol")
        bind_port = data.get("bind_port")
        if not isinstance(bind_port, int) or isinstance(bind_port, bool):
            raise RuntimeError(f"{CONFIG_ENV} contains an invalid bind port")
        binaries = data.get("startup_binaries", [])
        if not isinstance(binaries, list) or not all(isinstance(item, str) for item in binaries):
            raise RuntimeError(f"{CONFIG_ENV} contains invalid startup binaries")
        fingerprint = data.get("fingerprint")
        if not isinstance(fingerprint, str) or len(fingerprint) != 64:
            raise RuntimeError(f"{CONFIG_ENV} contains an invalid fingerprint")
        return cls(
            host_python=str(data["host_python"]),
            bn_python_path=Path(str(data["bn_python_path"])).absolute(),
            bind_host=str(data["bind_host"]),
            bind_port=bind_port,
            startup_timeout=_positive_number(data["startup_timeout"], "startup timeout"),
            idle_timeout=_positive_number(data["idle_timeout"], "idle timeout"),
            recovery_timeout=_positive_number(data["recovery_timeout"], "recovery timeout"),
            fingerprint=fingerprint,
            runtime_directory=Path(str(data["runtime_directory"])).absolute(),
            startup_binaries=tuple(str(Path(item).expanduser().resolve()) for item in binaries),
        )


def build_shared_host_config(
    *,
    host_python: str,
    bn_python_path: Path,
    bind_host: str,
    bind_port: int,
    startup_timeout: float,
    startup_binaries: list[str] | tuple[str, ...] = (),
) -> SharedHostConfig:
    if bind_port < 0 or bind_port > 65535:
        raise RuntimeError("headless HTTP port must be between 0 and 65535")
    fingerprint = _source_fingerprint(host_python, bn_python_path, bind_host, bind_port)
    runtime_directory = _default_runtime_root() / fingerprint[:24]
    idle = _positive_number(
        os.environ.get("BINJA_MCP_SHARED_HOST_IDLE_SEC", DEFAULT_IDLE_TIMEOUT_SEC),
        "BINJA_MCP_SHARED_HOST_IDLE_SEC",
    )
    recovery = _positive_number(
        os.environ.get("BINJA_MCP_HOST_RECOVERY_TIMEOUT_SEC", DEFAULT_RECOVERY_TIMEOUT_SEC),
        "BINJA_MCP_HOST_RECOVERY_TIMEOUT_SEC",
    )
    return SharedHostConfig(
        host_python=host_python,
        bn_python_path=bn_python_path,
        bind_host=bind_host,
        bind_port=bind_port,
        startup_timeout=_positive_number(startup_timeout, "startup timeout"),
        idle_timeout=idle,
        recovery_timeout=recovery,
        fingerprint=fingerprint,
        runtime_directory=runtime_directory,
        startup_binaries=tuple(
            str(Path(path).expanduser().resolve()) for path in startup_binaries
        ),
    )


def ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"Shared host path is not a real directory: {path}")
    getuid = getattr(os, "getuid", None)
    if callable(getuid) and info.st_uid != getuid():
        raise RuntimeError(f"Shared host directory is owned by another user: {path}")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o700:
        path.chmod(0o700)


def _open_private_file(path: Path, flags: int, mode: int = 0o600) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags | nofollow, mode)
    os.set_inheritable(descriptor, False)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise RuntimeError(f"Shared host path is not a regular file: {path}")
    getuid = getattr(os, "getuid", None)
    if callable(getuid) and info.st_uid != getuid():
        os.close(descriptor)
        raise RuntimeError(f"Shared host file is owned by another user: {path}")
    if os.name != "nt":
        os.fchmod(descriptor, mode)
    return descriptor


def _lock_file(file: BinaryIO, *, blocking: bool) -> bool:
    if os.name == "nt":
        import msvcrt

        file.seek(0, os.SEEK_END)
        if file.tell() == 0:
            file.write(b"\0")
            file.flush()
        file.seek(0)
        operation = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
        try:
            msvcrt.locking(file.fileno(), operation, 1)
            return True
        except OSError:
            return False

    import fcntl

    operation = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    try:
        fcntl.flock(file.fileno(), operation)
        return True
    except BlockingIOError:
        return False


def _unlock_file(file: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        file.seek(0)
        msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(file.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    ensure_private_directory(path.parent)
    descriptor = _open_private_file(path, os.O_RDWR | os.O_CREAT)
    with os.fdopen(descriptor, "a+b", buffering=0) as lock_file:
        if not _lock_file(lock_file, blocking=True):
            raise RuntimeError(f"Could not lock shared host state: {path}")
        try:
            yield
        finally:
            _unlock_file(lock_file)


class ClientLease:
    def __init__(self, path: Path, file: BinaryIO, registry_lock: Path):
        self.path = path
        self.file = file
        self.registry_lock = registry_lock

    def close(self) -> None:
        if self.file.closed:
            return
        with exclusive_lock(self.registry_lock):
            if os.name == "nt":
                _unlock_file(self.file)
                self.file.close()
                try:
                    self.path.unlink(missing_ok=True)
                except OSError:
                    pass
            else:
                try:
                    self.path.unlink(missing_ok=True)
                finally:
                    try:
                        _unlock_file(self.file)
                    finally:
                        self.file.close()

    def __enter__(self) -> ClientLease:
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()


def create_client_lease(config: SharedHostConfig) -> ClientLease:
    ensure_private_directory(config.runtime_directory.parent)
    ensure_private_directory(config.runtime_directory)
    ensure_private_directory(config.lease_directory)
    path = config.lease_directory / f"client-{os.getpid()}-{secrets.token_hex(8)}.lease"
    with exclusive_lock(config.lease_lock_file):
        if _active_client_leases_unlocked(config.lease_directory) == 0:
            # A SIGKILLed native host cannot run its idle monitor to clear the
            # previous session. Do that before publishing the first lease of a
            # new client epoch, but preserve a healthy (or merely slow) host
            # during its configured warm-idle grace period.
            record = _read_host_record(config)
            health = probe_host_status(record) if record is not None else "dead"
            if health == "dead":
                config.state_file.unlink(missing_ok=True)
                config.session_file.unlink(missing_ok=True)
        descriptor = _open_private_file(path, os.O_RDWR | os.O_CREAT | os.O_EXCL)
        file = os.fdopen(descriptor, "w+b", buffering=0)
        try:
            file.write((json.dumps({"pid": os.getpid()}) + "\n").encode("utf-8"))
            file.flush()
            if not _lock_file(file, blocking=True):
                raise RuntimeError(f"Could not acquire Binary Ninja client lease: {path}")
            return ClientLease(path, file, config.lease_lock_file)
        except Exception:
            file.close()
            path.unlink(missing_ok=True)
            raise


def _lease_is_active(path: Path) -> bool:
    try:
        descriptor = _open_private_file(path, os.O_RDWR)
    except (FileNotFoundError, OSError, RuntimeError):
        return False
    file = os.fdopen(descriptor, "r+b", buffering=0)
    try:
        if not _lock_file(file, blocking=False):
            return True
        try:
            _unlock_file(file)
        finally:
            file.close()
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return False
    finally:
        if not file.closed:
            file.close()


def _active_client_leases_unlocked(directory: Path) -> int:
    try:
        paths = list(directory.glob("*.lease"))
    except OSError:
        return 0
    return sum(1 for path in paths if _lease_is_active(path))


def active_client_leases(directory: Path) -> int:
    with exclusive_lock(directory.parent / "clients.lock"):
        return _active_client_leases_unlocked(directory)


def _claim_idle_shutdown(
    lease_directory: Path,
    state_file: Path,
    instance_id: str,
) -> bool:
    """Atomically reject a new lease before clearing one finished session."""
    with exclusive_lock(lease_directory.parent / "clients.lock"):
        if _active_client_leases_unlocked(lease_directory):
            return False
        if _state_instance(state_file) != instance_id:
            return True
        # Recovery state belongs only to the current set of MCP client leases;
        # do not make a later, unrelated Codex session reopen every historical
        # (potentially multi-GiB) target.
        (state_file.parent / "binaries.json").unlink(missing_ok=True)
        state_file.unlink(missing_ok=True)
        return True


def _state_instance(path: Path) -> str | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        return None
    value = data.get("instance_id") if isinstance(data, dict) else None
    return value if isinstance(value, str) else None


def monitor_shared_host_lifetime(
    stopping: threading.Event,
    lease_directory: Path,
    state_file: Path,
    instance_id: str,
    idle_timeout: float,
    claim_timeout: float = 30.0,
) -> None:
    """Stop a detached host after supersession or the last client lease."""
    claim_deadline = time.monotonic() + claim_timeout
    missing_since: float | None = None
    idle_since: float | None = None
    claimed = False
    while not stopping.wait(0.25):
        now = time.monotonic()
        current_instance = _state_instance(state_file)
        if current_instance == instance_id:
            claimed = True
            missing_since = None
        elif current_instance is not None:
            stopping.set()
            return
        elif claimed:
            missing_since = missing_since or now
            if now - missing_since >= 5.0:
                stopping.set()
                return
        elif now >= claim_deadline:
            stopping.set()
            return

        if active_client_leases(lease_directory):
            idle_since = None
        else:
            idle_since = idle_since or now
            if now - idle_since >= idle_timeout:
                if _claim_idle_shutdown(lease_directory, state_file, instance_id):
                    stopping.set()
                    return
                idle_since = None


def host_environment(bn_python_path: Path) -> dict[str, str]:
    if not (bn_python_path / "binaryninja").is_dir():
        raise FileNotFoundError(f"binaryninja package not found below: {bn_python_path}")
    environment = os.environ.copy()
    current_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(bn_python_path) + (
        os.pathsep + current_pythonpath if current_pythonpath else ""
    )
    if sys.platform == "darwin":
        macos_dir = bn_python_path.parents[1] / "MacOS"
        current_dyld_path = environment.get("DYLD_LIBRARY_PATH")
        environment["DYLD_LIBRARY_PATH"] = str(macos_dir) + (
            os.pathsep + current_dyld_path if current_dyld_path else ""
        )
    environment["BN_DISABLE_USER_PLUGINS"] = "1"
    environment["BN_DISABLE_REPOSITORY_PLUGINS"] = "1"
    environment["BN_MCP_HEADLESS"] = "1"
    return environment


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
    source = source or default_binary_ninja_user_directory(environment)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    license_file = source / "license.dat"
    if "BN_LICENSE" not in environment and license_file.is_file():
        environment["BN_LICENSE"] = license_file.read_text(encoding="utf-8")
    settings_file = source / "settings.json"
    if settings_file.is_file():
        shutil.copy2(settings_file, destination / "settings.json")
    environment["BN_USER_DIRECTORY"] = str(destination)


def _atomic_json_write(path: Path, data: object) -> None:
    ensure_private_directory(path.parent)
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    descriptor = _open_private_file(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
    )
    try:
        encoded = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        if os.name != "nt":
            path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _read_host_record(config: SharedHostConfig, *, require_ready: bool = True) -> HostRecord | None:
    try:
        descriptor = _open_private_file(config.state_file, os.O_RDONLY)
    except (FileNotFoundError, OSError, RuntimeError):
        return None
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8") as state:
            data = json.load(state)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("protocol") != REGISTRY_PROTOCOL or data.get("fingerprint") != config.fingerprint:
        return None
    host = data.get("host")
    port = data.get("port")
    instance_id = data.get("instance_id")
    pid = data.get("pid")
    token = data.get("auth_token")
    ready = data.get("ready") is True
    if host != config.bind_host:
        return None
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return None
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    if not isinstance(instance_id, str) or len(instance_id) < 16:
        return None
    if not isinstance(token, str) or len(token) < 32:
        return None
    if require_ready and not ready:
        return None
    return HostRecord(HostEndpoint(host, port, instance_id), pid, token, config.fingerprint, ready)


def _write_host_record(config: SharedHostConfig, record: HostRecord) -> None:
    _atomic_json_write(
        config.state_file,
        {
            "protocol": REGISTRY_PROTOCOL,
            "fingerprint": record.fingerprint,
            "host": record.endpoint.host,
            "port": record.endpoint.port,
            "instance_id": record.endpoint.instance_id,
            "pid": record.pid,
            "auth_token": record.auth_token,
            "ready": record.ready,
        },
    )


def _host_url(endpoint: HostEndpoint, path: str) -> str:
    host = endpoint.host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"http://{host}:{endpoint.port}/{path.lstrip('/')}"


def process_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        return exc.errno == errno.EPERM


def probe_host_status(record: HostRecord, timeout: float = 1.0) -> str:
    """Return healthy, dead, or unknown without mistaking a timeout for death."""
    if not process_is_alive(record.pid):
        return "dead"
    request = urllib.request.Request(
        _host_url(record.endpoint, "health"),
        headers={"X-Binary-Ninja-MCP-Token": record.auth_token},
    )
    try:
        with DIRECT_HTTP_OPENER.open(request, timeout=timeout) as response:
            data = json.load(response)
    except urllib.error.HTTPError:
        return "dead"
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, (TimeoutError, socket.timeout)):
            return "unknown"
        if isinstance(reason, OSError) and reason.errno in {
            errno.ECONNREFUSED,
            errno.ECONNRESET,
            errno.EPIPE,
        }:
            return "dead"
        return "unknown"
    except TimeoutError:
        return "unknown"
    except (http.client.IncompleteRead, http.client.RemoteDisconnected):
        return "dead"
    except OSError as exc:
        if exc.errno in {errno.ECONNREFUSED, errno.ECONNRESET, errno.EPIPE}:
            return "dead"
        return "unknown"
    except (UnicodeError, json.JSONDecodeError):
        return "dead"
    healthy = bool(
        response.status == 200
        and isinstance(data, dict)
        and data.get("protocol") == HEALTH_PROTOCOL
        and data.get("instance_id") == record.endpoint.instance_id
        and data.get("pid") == record.pid
    )
    return "healthy" if healthy else "dead"


def probe_host(record: HostRecord, timeout: float = 1.0) -> bool:
    return probe_host_status(record, timeout) == "healthy"


def read_ready_file(
    ready_file: Path,
    *,
    expected_instance_id: str,
    expected_pid: int,
    expected_host: str,
) -> HostEndpoint | None:
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
) -> HostEndpoint:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        return_code = process.poll()
        if return_code is not None:
            raise RuntimeError(f"Binary Ninja headless host exited during startup ({return_code})")
        endpoint = read_ready_file(
            ready_file,
            expected_instance_id=expected_instance_id,
            expected_pid=process.pid,
            expected_host=expected_host,
        )
        if endpoint is not None:
            record = HostRecord(endpoint, process.pid, auth_token, "pending", True)
            if probe_host(record, timeout=0.5):
                return endpoint
        time.sleep(0.05)
    raise TimeoutError("Timed out waiting for the shared Binary Ninja headless host")


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _tail(path: Path, limit: int = 5000) -> str:
    try:
        with path.open("rb") as source:
            source.seek(0, os.SEEK_END)
            size = source.tell()
            source.seek(max(0, size - limit))
            return source.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _read_session(config: SharedHostConfig) -> list[dict[str, object]]:
    try:
        data = json.loads(config.session_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SessionRestoreError(
            f"Cannot read Binary Ninja recovery manifest: {config.session_file}: {exc}"
        ) from exc
    if not isinstance(data, list):
        raise SessionRestoreError("Binary Ninja recovery manifest is not a list")
    records: list[dict[str, object]] = []
    for item in data:
        if not isinstance(item, dict) or not isinstance(item.get("filepath"), str):
            raise SessionRestoreError("Binary Ninja recovery manifest contains an invalid entry")
        view_id = item.get("view_id")
        if not isinstance(view_id, int) or isinstance(view_id, bool) or view_id <= 0:
            raise SessionRestoreError(
                f"Binary Ninja recovery target has an invalid stable view id: {item.get('filepath')}"
            )
        records.append(dict(item))
    return sorted(records, key=lambda item: int(item["view_id"]))


def remember_binary(
    config: SharedHostConfig,
    payload: dict[str, object],
    view_id: str | int | None,
) -> None:
    filepath = payload.get("filepath")
    if not isinstance(filepath, str) or not filepath:
        return
    canonical = str(Path(filepath).expanduser().resolve())
    record: dict[str, object] = {
        "filepath": canonical,
        "analysis_mode": str(payload.get("analysis_mode") or "basic"),
        "platform": str(payload.get("platform") or ""),
        "image_base": str(payload.get("image_base") or ""),
    }
    try:
        stable_view_id = int(str(view_id))
    except (TypeError, ValueError) as exc:
        raise SessionRestoreError(
            f"Cannot journal Binary Ninja target without a stable view id: {canonical}"
        ) from exc
    if stable_view_id <= 0:
        raise SessionRestoreError(
            f"Cannot journal Binary Ninja target with invalid view id {view_id!r}: {canonical}"
        )
    record["view_id"] = stable_view_id
    with exclusive_lock(config.session_lock_file):
        records = _read_session(config)
        for index, existing in enumerate(records):
            if existing.get("filepath") == canonical:
                records[index] = record
                break
        else:
            records.append(record)
        _atomic_json_write(config.session_file, records)


def remember_binary_for_instance(
    config: SharedHostConfig,
    instance_id: str,
    payload: dict[str, object],
    view_id: str | int | None,
) -> None:
    """Journal only while this native host still owns the client epoch."""
    with exclusive_lock(config.lease_lock_file):
        current = _read_host_record(config, require_ready=False)
        if current is None or current.endpoint.instance_id != instance_id:
            raise SessionRestoreError(
                "Refusing to journal a Binary Ninja load from a stopped or "
                f"superseded host instance: {instance_id}"
            )
        # Keep the epoch lock through the session-file replacement. Idle
        # cleanup uses the same lock, so it either removes this completed write
        # or wins first and makes the instance check fail without recreation.
        remember_binary(config, payload, view_id)


def _load_binary(record: HostRecord, payload: dict[str, object], timeout: float) -> dict:
    request = urllib.request.Request(
        _host_url(record.endpoint, "load"),
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Binary-Ninja-MCP-Token": record.auth_token,
        },
        method="POST",
    )
    try:
        with DIRECT_HTTP_OPENER.open(request, timeout=timeout) as response:
            data = json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            detail = json.load(exc)
        except Exception:
            detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Binary Ninja load failed ({exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            raise HostResponseTimedOut(
                "Timed out while loading a Binary Ninja recovery target"
            ) from exc
        raise HostConnectionLost(f"Binary Ninja load connection failed: {exc}") from exc
    except TimeoutError as exc:
        raise HostResponseTimedOut(
            "Timed out while loading a Binary Ninja recovery target"
        ) from exc
    except (
        ConnectionError,
        BrokenPipeError,
        http.client.IncompleteRead,
        http.client.RemoteDisconnected,
    ) as exc:
        raise HostConnectionLost(f"Binary Ninja load connection failed: {exc}") from exc
    if not isinstance(data, dict) or data.get("error"):
        raise RuntimeError(f"Binary Ninja load failed: {data}")
    return data


class SharedHostRuntime:
    """Resolve, lazily create, and recover the shared native host."""

    def __init__(self, config: SharedHostConfig):
        self.config = config
        self._thread_lock = threading.RLock()
        self._startup_loaded_generation = ""
        self._verified_generation = ""

    @classmethod
    def from_environment(cls) -> SharedHostRuntime | None:
        config = SharedHostConfig.from_environment()
        return cls(config) if config is not None else None

    def current_record(self) -> HostRecord | None:
        return _read_host_record(self.config)

    def remember_binary(self, payload: dict[str, object], view_id: str | int | None) -> None:
        remember_binary(self.config, payload, view_id)

    def remember_binary_for_instance(
        self,
        instance_id: str,
        payload: dict[str, object],
        view_id: str | int | None,
    ) -> None:
        remember_binary_for_instance(self.config, instance_id, payload, view_id)

    def ensure_host(self, *, previous_instance: str = "") -> HostRecord:
        with self._thread_lock:
            deadline = time.monotonic() + self.config.recovery_timeout
            while True:
                record = _read_host_record(self.config)
                if record is not None and (
                    not previous_instance or record.endpoint.instance_id != previous_instance
                ):
                    if (
                        record.endpoint.instance_id == self._verified_generation
                        and process_is_alive(record.pid)
                    ):
                        return self._ensure_startup_binaries(record)
                    health = probe_host_status(record)
                    if health == "healthy":
                        self._verified_generation = record.endpoint.instance_id
                        return self._ensure_startup_binaries(record)
                    if health == "unknown":
                        raise RuntimeError(
                            "Shared Binary Ninja host health check timed out; "
                            "refusing to replace an unproven-dead host"
                        )
                try:
                    record = self._ensure_host_locked(previous_instance=previous_instance)
                    return self._ensure_startup_binaries(record)
                except SessionRestoreError:
                    raise
                except RuntimeError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)

    def recover_after_connection_loss(self, previous_instance: str) -> HostRecord:
        """Keep a healthy generation; replace only a host that fails health."""
        with self._thread_lock:
            current = _read_host_record(self.config)
            if current is not None and current.endpoint.instance_id == previous_instance:
                health = probe_host_status(current)
                if health != "dead":
                    if health == "healthy":
                        self._verified_generation = current.endpoint.instance_id
                    return current
            return self.ensure_host(previous_instance=previous_instance)

    def _ensure_host_locked(self, *, previous_instance: str) -> HostRecord:
        ensure_private_directory(self.config.runtime_directory.parent)
        ensure_private_directory(self.config.runtime_directory)
        ensure_private_directory(self.config.lease_directory)
        with exclusive_lock(self.config.state_lock_file):
            record = _read_host_record(self.config)
            if record is not None and (
                not previous_instance or record.endpoint.instance_id != previous_instance
            ):
                health = probe_host_status(record)
                if health == "healthy":
                    self._verified_generation = record.endpoint.instance_id
                    return record
                if health == "unknown":
                    raise RuntimeError(
                        "Shared Binary Ninja host health check timed out; "
                        "refusing to replace an unproven-dead host"
                    )
            self.config.state_file.unlink(missing_ok=True)
            return self._spawn_host()

    def _spawn_host(self) -> HostRecord:
        instance_id = secrets.token_hex(16)
        auth_token = secrets.token_urlsafe(32)
        ready_file = self.config.runtime_directory / f"ready-{instance_id}.json"
        user_directory = self.config.runtime_directory / f"user-{instance_id}"
        environment = host_environment(self.config.bn_python_path)
        prepare_isolated_user_directory(environment, user_directory)
        environment["BINJA_MCP_INSTANCE_ID"] = instance_id
        environment["BINJA_MCP_AUTH_TOKEN"] = auth_token
        command = [
            self.config.host_python,
            str(REPO_ROOT / "bridge" / "headless_host.py"),
            "--host",
            self.config.bind_host,
            "--port",
            str(self.config.bind_port),
            "--ready-file",
            str(ready_file),
            "--lease-directory",
            str(self.config.lease_directory),
            "--shared-state-file",
            str(self.config.state_file),
            "--idle-timeout",
            str(self.config.idle_timeout),
            "--claim-timeout",
            str(max(30.0, self.config.startup_timeout + 5.0)),
        ]
        log_descriptor = _open_private_file(
            self.config.log_file,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        )
        process: subprocess.Popen | None = None
        try:
            with os.fdopen(log_descriptor, "ab", buffering=0) as log:
                popen_kwargs: dict[str, object] = {
                    "env": environment,
                    "stdin": subprocess.DEVNULL,
                    "stdout": log,
                    "stderr": subprocess.STDOUT,
                    "close_fds": True,
                }
                if os.name != "nt":
                    popen_kwargs["start_new_session"] = True
                process = subprocess.Popen(command, **popen_kwargs)
            endpoint = wait_for_host(
                process,
                ready_file,
                instance_id,
                self.config.bind_host,
                auth_token,
                self.config.startup_timeout,
            )
            pending = HostRecord(
                endpoint,
                process.pid,
                auth_token,
                self.config.fingerprint,
                False,
            )
            _write_host_record(self.config, pending)
            self._restore_binaries(pending)
            ready = pending._replace(ready=True)
            _write_host_record(self.config, ready)
            self._verified_generation = ready.endpoint.instance_id
            print(
                f"Shared Binary Ninja host ready (pid={process.pid}, "
                f"instance={instance_id}, log={self.config.log_file})",
                file=sys.stderr,
                flush=True,
            )
            return ready
        except Exception as exc:
            stop_process(process)
            self.config.state_file.unlink(missing_ok=True)
            diagnostics = _tail(self.config.log_file)
            detail = f"\n{diagnostics}" if diagnostics else ""
            if isinstance(exc, SessionRestoreError):
                raise SessionRestoreError(f"{exc}{detail}") from exc
            raise RuntimeError(f"Shared Binary Ninja host startup failed: {exc}{detail}") from exc
        finally:
            ready_file.unlink(missing_ok=True)

    def _restore_binaries(self, record: HostRecord) -> None:
        timeout = _positive_number(
            os.environ.get("BINJA_MCP_HTTP_READ_TIMEOUT_SEC", 1740.0),
            "BINJA_MCP_HTTP_READ_TIMEOUT_SEC",
        )
        for payload in _read_session(self.config):
            filepath = str(payload.get("filepath") or "")
            if not Path(filepath).is_file():
                raise SessionRestoreError(
                    "Cannot restore Binary Ninja views without changing stable view ids: "
                    f"recorded target is missing: {filepath}"
                )
            try:
                data = _load_binary(record, payload, timeout)
                expected_view_id = payload.get("view_id")
                if expected_view_id is not None and str(data.get("view_id")) != str(
                    expected_view_id
                ):
                    raise SessionRestoreError(
                        "Binary Ninja recovery changed a stable view id: "
                        f"{filepath} expected view:{expected_view_id}, "
                        f"got view:{data.get('view_id')}"
                    )
                remember_binary(self.config, payload, data.get("view_id"))
            except (HostConnectionLost, HostResponseTimedOut, SessionRestoreError):
                raise
            except Exception as exc:
                raise SessionRestoreError(
                    f"Cannot restore Binary Ninja target {filepath}: {exc}"
                ) from exc

    def _ensure_startup_binaries(self, record: HostRecord) -> HostRecord:
        if (
            not self.config.startup_binaries
            or self._startup_loaded_generation == record.endpoint.instance_id
        ):
            return record
        timeout = _positive_number(
            os.environ.get("BINJA_MCP_HTTP_READ_TIMEOUT_SEC", 1740.0),
            "BINJA_MCP_HTTP_READ_TIMEOUT_SEC",
        )
        for filepath in self.config.startup_binaries:
            payload: dict[str, object] = {
                "filepath": filepath,
                "analysis_mode": "basic",
                "platform": "",
                "image_base": "",
            }
            try:
                data = _load_binary(record, payload, timeout)
            except HostConnectionLost:
                record = self.recover_after_connection_loss(record.endpoint.instance_id)
                if self._startup_loaded_generation == record.endpoint.instance_id:
                    return record
                data = _load_binary(record, payload, timeout)
            remember_binary(self.config, payload, data.get("view_id"))
        self._startup_loaded_generation = record.endpoint.instance_id
        return record
