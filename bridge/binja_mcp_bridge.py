import sys as _sys
import traceback as _tb


# Install a very-early excepthook so any ImportError at module import time is captured.
def _bridge_excepthook(exc_type, exc, tb):
    # Print to stderr for interactive runs
    _tb.print_exception(exc_type, exc, tb, file=_sys.stderr)


_sys.excepthook = _bridge_excepthook

import base64 as _base64
import contextvars as _contextvars
import functools as _functools
import inspect as _inspect
import math as _math
import os as _os
import threading as _threading
import time as _time
from typing import NamedTuple as _NamedTuple

import requests

try:
    from shared_host import SharedHostRuntime as _SharedHostRuntime
except ModuleNotFoundError:
    # ``importlib.util.spec_from_file_location`` (used by tests and some MCP
    # clients) does not automatically add this script's directory to sys.path.
    _sys.path.insert(0, _os.path.dirname(_os.path.realpath(__file__)))
    from shared_host import SharedHostRuntime as _SharedHostRuntime

try:
    from mcp.server.fastmcp import FastMCP
except ModuleNotFoundError:
    # MCP SDK 2.x renamed the ergonomic server class while retaining the
    # decorator and stdio run interfaces used by this bridge.
    from mcp.server.mcpserver import MCPServer as FastMCP

_binja_host = _os.environ.get("BINJA_MCP_HOST", "localhost")
_binja_port = _os.environ.get("BINJA_MCP_PORT", "9009")
_binja_auth_token = _os.environ.get("BINJA_MCP_AUTH_TOKEN", "")
binja_server_url = f"http://{_binja_host}:{_binja_port}"
mcp = FastMCP("binja-mcp")
_target_binary = _contextvars.ContextVar("binary_ninja_mcp_target", default="")
_shared_host_runtime = _SharedHostRuntime.from_environment()


class _HttpEndpoint(_NamedTuple):
    url: str
    auth_token: str
    instance_id: str


class _MutationOutcomeUnknown(RuntimeError):
    """The connection died after a mutation may have reached the old host."""


def _endpoint(previous_instance: str = "") -> _HttpEndpoint:
    if _shared_host_runtime is None:
        return _HttpEndpoint(binja_server_url, _binja_auth_token, "")
    record = _shared_host_runtime.ensure_host(previous_instance=previous_instance)
    return _endpoint_from_record(record)


def _endpoint_from_record(record) -> _HttpEndpoint:
    host = record.endpoint.host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return _HttpEndpoint(
        f"http://{host}:{record.endpoint.port}",
        record.auth_token,
        record.endpoint.instance_id,
    )


def _positive_timeout_from_env(name: str, default: float) -> float:
    raw_value = _os.environ.get(name)
    if raw_value is None:
        return default
    try:
        value = float(raw_value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive number, got {raw_value!r}") from exc
    if not _math.isfinite(value) or value <= 0:
        raise RuntimeError(f"{name} must be a positive finite number, got {raw_value!r}")
    return value


_HTTP_CONNECT_TIMEOUT_SEC = _positive_timeout_from_env("BINJA_MCP_HTTP_CONNECT_TIMEOUT_SEC", 5.0)
# Leave one minute for MCP response serialization inside Codex's installed
# 30-minute tool wait budget. This is an inactivity timeout in requests, not a
# deadline for Binary Ninja analysis itself.
_HTTP_READ_TIMEOUT_SEC = _positive_timeout_from_env("BINJA_MCP_HTTP_READ_TIMEOUT_SEC", 1740.0)
_DEFAULT_HTTP_TIMEOUT = (_HTTP_CONNECT_TIMEOUT_SEC, _HTTP_READ_TIMEOUT_SEC)


class _ThreadLocalHttpClient:
    """Give each MCP worker its own requests session.

    FastMCP may execute synchronous tools on several worker threads. A shared
    ``requests.Session`` is mutable and is not a request-isolation boundary, so
    keeping it global makes otherwise independent agents share connection and
    cookie state. The wrapper retains the small verb-based interface used by
    the bridge and creates one proxy-free session per worker thread.
    """

    def __init__(self, session_factory=requests.Session):
        self._local = _threading.local()
        self._session_factory = session_factory

    @property
    def trust_env(self) -> bool:
        """Expose the effective policy for diagnostics and compatibility tests."""
        return False

    def _session(self):
        session = getattr(self._local, "session", None)
        if session is None:
            session = self._session_factory()
            # Authenticated loopback traffic must not inherit
            # HTTP_PROXY/HTTPS_PROXY/ALL_PROXY.
            session.trust_env = False
            self._local.session = session
        return session

    def get(self, *args, **kwargs):
        return self._session().get(*args, **kwargs)

    def post(self, *args, **kwargs):
        return self._session().post(*args, **kwargs)

    def delete(self, *args, **kwargs):
        return self._session().delete(*args, **kwargs)


_http = _ThreadLocalHttpClient()
_mutating_get_endpoints = frozenset(
    {
        "declareCType",
        "defineTypes",
        "formatValue",
        "makeFunctionAt",
        "patch",
        "renameVariable",
        "renameVariables",
        "retypeVariable",
        "setFunctionPrototype",
        "setLocalVariableType",
    }
)


def _effective_timeout(
    endpoint: str,
    requested: float | tuple[float, float | None] | None,
) -> float | tuple[float, float | None]:
    """Give accepted operations a long, finite response-read budget.

    The Binary Ninja host serializes access to mutable analysis state. Under
    concurrent agents, a healthy request can therefore wait behind a long
    decompile or IL operation. A scalar requests timeout applies to both
    connect and response reads, so the old five-second default abandoned these
    queued requests while they were still live in the host. Keep loopback
    connection setup bounded and allow queued work to finish within the MCP
    client's configured wait budget. Mutations always use this long policy
    because retrying an early-abandoned mutation can apply it twice.
    """
    if requested is None or endpoint.strip("/") in _mutating_get_endpoints:
        return _DEFAULT_HTTP_TIMEOUT
    return requested


def _request_headers(auth_token: str | None = None) -> dict[str, str]:
    headers: dict[str, str] = {}
    token = _binja_auth_token if auth_token is None else auth_token
    if token:
        headers["X-Binary-Ninja-MCP-Token"] = token
    target = _target_binary.get().strip()
    if target:
        # HTTP header values are Latin-1 and reject newlines. Base64url keeps
        # every valid Unicode path/selector representable and header-safe.
        headers["X-Binary-Ninja-View-B64"] = _base64.urlsafe_b64encode(
            target.encode("utf-8")
        ).decode("ascii")
    return headers


def _request(
    method: str,
    endpoint: str,
    *,
    retry_safe: bool,
    **kwargs,
):
    """Send through the current host and recover only on connection loss.

    A response-read timeout can mean a healthy Binary Ninja operation is still
    running behind the server's serialization lock, so it never replaces the
    host.  A connection/reset failure does trigger a new registry generation.
    Read-only operations and canonical-path ``/load`` may then be replayed;
    mutations return an explicit unknown-outcome error instead.
    """
    current = _endpoint()

    def send(target: _HttpEndpoint):
        request_kwargs = dict(kwargs)
        headers = dict(request_kwargs.pop("headers", {}) or {})
        headers.update(_request_headers(target.auth_token))
        return getattr(_http, method.lower())(
            f"{target.url}/{endpoint.lstrip('/')}",
            headers=headers,
            **request_kwargs,
        )

    try:
        return send(current)
    except requests.exceptions.ReadTimeout as exc:
        if retry_safe:
            raise
        raise _MutationOutcomeUnknown(
            "Timed out waiting for Binary Ninja after the mutation may have been "
            "accepted. The host was not replaced and this mutation was not replayed; "
            "its outcome is unknown. Inspect the target before retrying."
        ) from exc
    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.ConnectTimeout,
        requests.exceptions.ChunkedEncodingError,
    ) as exc:
        if _shared_host_runtime is None:
            raise
        replacement = _endpoint_from_record(
            _shared_host_runtime.recover_after_connection_loss(current.instance_id)
        )
        if retry_safe:
            return send(replacement)
        raise _MutationOutcomeUnknown(
            "Binary Ninja host connection was lost after the request may have been "
            "accepted. The shared host recovered, but this mutation was not replayed; "
            "its outcome is unknown. Inspect the target before retrying."
        ) from exc


_raw_mcp_tool = mcp.tool
_unscoped_tool_names = {
    "close_binary",
    "convert_number",
    "list_binaries",
    "list_platforms",
    "open_binary",
    "select_binary",
}


def scoped_tool(*decorator_args, **decorator_kwargs):
    """Add an optional immutable binary selector to every analysis tool.

    Codex can multiplex several agents through one stdio MCP connection, so a
    prior ``select_binary`` call is not a safe session boundary. The selector
    becomes an HTTP header on every request made by this tool invocation.
    """
    register = _raw_mcp_tool(*decorator_args, **decorator_kwargs)

    def decorate(function):
        if function.__name__ in _unscoped_tool_names:
            return register(function)

        signature = _inspect.signature(function)
        binary_parameter = _inspect.Parameter(
            "binary",
            kind=_inspect.Parameter.KEYWORD_ONLY,
            default="",
            annotation=str,
        )

        @_functools.wraps(function)
        def scoped(*args, binary: str = "", **kwargs):
            reset_token = None
            if binary.strip():
                reset_token = _target_binary.set(binary.strip())
            try:
                return function(*args, **kwargs)
            finally:
                if reset_token is not None:
                    _target_binary.reset(reset_token)

        scoped.__signature__ = signature.replace(  # type: ignore[attr-defined]
            parameters=[*signature.parameters.values(), binary_parameter]
        )
        scope_help = (
            "\n\nbinary: Stable view:N selector or absolute filename. Supply this on every "
            "target-dependent call when agents may run concurrently."
        )
        scoped.__doc__ = (function.__doc__ or "") + scope_help
        return register(scoped)

    return decorate


def _exit_when_parent_dies(parent_pid: int) -> None:
    """Ensure an abruptly killed launcher cannot orphan the stdio bridge."""
    if _sys.platform == "win32":
        import ctypes as _ctypes
        from ctypes import wintypes as _wintypes

        synchronize = 0x00100000
        wait_timeout = 0x00000102
        kernel32 = _ctypes.windll.kernel32
        kernel32.OpenProcess.argtypes = [
            _wintypes.DWORD,
            _wintypes.BOOL,
            _wintypes.DWORD,
        ]
        kernel32.OpenProcess.restype = _wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = [_wintypes.HANDLE, _wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = _wintypes.DWORD
        kernel32.CloseHandle.argtypes = [_wintypes.HANDLE]
        kernel32.CloseHandle.restype = _wintypes.BOOL
        handle = kernel32.OpenProcess(synchronize, False, parent_pid)
        if not handle:
            _os._exit(1)
        try:
            while kernel32.WaitForSingleObject(handle, 1000) == wait_timeout:
                pass
        finally:
            kernel32.CloseHandle(handle)
        _os._exit(1)

    while _os.getppid() == parent_pid:
        _time.sleep(0.5)
    _os._exit(1)


def _start_parent_watchdog() -> None:
    value = _os.environ.get("BINJA_MCP_PARENT_PID", "").strip()
    if not value:
        return
    try:
        parent_pid = int(value)
    except ValueError:
        raise RuntimeError("BINJA_MCP_PARENT_PID must be an integer")
    if parent_pid <= 0:
        raise RuntimeError("BINJA_MCP_PARENT_PID must be positive")
    _threading.Thread(
        target=_exit_when_parent_dies,
        args=(parent_pid,),
        daemon=True,
        name="binary-ninja-mcp-launcher-watch",
    ).start()


def _active_filename() -> str:
    """Return the currently active filename as known by the server."""
    try:
        st = get_json("status")
        if isinstance(st, dict) and st.get("filename"):
            return str(st.get("filename"))
    except Exception:
        pass
    return "(none)"


def safe_get(
    endpoint: str,
    params: dict | None = None,
    timeout: float | tuple[float, float | None] | None = None,
) -> list:
    """
    Perform a GET request. If 'params' is given, we convert it to a query string.
    """
    if params is None:
        params = {}
    timeout = _effective_timeout(endpoint, timeout)
    try:
        response = _request(
            "get",
            endpoint,
            retry_safe=endpoint.strip("/") not in _mutating_get_endpoints,
            params=params,
            timeout=timeout,
        )
        response.encoding = "utf-8"
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {e!s}"]


def get_json(
    endpoint: str,
    params: dict | None = None,
    timeout: float | tuple[float, float | None] | None = None,
):
    """
    Perform a GET and return parsed JSON.
    - On 2xx: returns parsed JSON.
    - On 4xx/5xx: attempts to parse JSON body and return it; if not JSON, returns {'error': 'Error <code>: <text>'}.
    Returns None only on transport errors.
    """
    if params is None:
        params = {}
    timeout = _effective_timeout(endpoint, timeout)
    try:
        response = _request(
            "get",
            endpoint,
            retry_safe=endpoint.strip("/") not in _mutating_get_endpoints,
            params=params,
            timeout=timeout,
        )
        response.encoding = "utf-8"
        # Try to parse JSON regardless of status
        try:
            data = response.json()
        except Exception:
            data = None
        if response.ok:
            return data
        # Non-OK: return parsed error object if available; otherwise synthesize one
        if isinstance(data, dict):
            # Ensure at least an error field for LLMs
            if "error" not in data:
                data = {"error": str(data)}
            data.setdefault("status", response.status_code)
            return data
        text = (response.text or "").strip()
        return {"error": f"Error {response.status_code}: {text}"}
    except Exception as e:
        return {"error": f"Request failed: {e!s}"}


def get_text(
    endpoint: str,
    params: dict | None = None,
    timeout: float | tuple[float, float | None] | None = None,
) -> str:
    """Perform a GET and return raw text (or an error string)."""
    if params is None:
        params = {}
    timeout = _effective_timeout(endpoint, timeout)
    try:
        response = _request(
            "get",
            endpoint,
            retry_safe=endpoint.strip("/") not in _mutating_get_endpoints,
            params=params,
            timeout=timeout,
        )
        response.encoding = "utf-8"
        if response.ok:
            return response.text
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {e!s}"


def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        timeout = _effective_timeout(endpoint, None)
        if isinstance(data, dict):
            response = _request(
                "post",
                endpoint,
                retry_safe=False,
                data=data,
                timeout=timeout,
            )
        else:
            response = _request(
                "post",
                endpoint,
                retry_safe=False,
                data=data.encode("utf-8"),
                timeout=timeout,
            )
        response.encoding = "utf-8"
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {e!s}"


def safe_delete(endpoint: str, params: dict | None = None) -> str:
    """Perform a DELETE request and return raw text (or an error string)."""
    try:
        response = _request(
            "delete",
            endpoint,
            retry_safe=False,
            params=params or {},
            timeout=_effective_timeout(endpoint, None),
        )
        response.encoding = "utf-8"
        if response.ok:
            return response.text.strip()
        return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {e!s}"


@scoped_tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    header = f"File: {_active_filename()}"
    body = safe_get("methods", {"offset": offset, "limit": limit})
    return [header] + (body or [])


@scoped_tool()
def get_entry_points() -> list:
    """
    List entry point(s) of the loaded binary.
    """
    data = get_json("entryPoints")
    if not data or "entry_points" not in data:
        return ["Error: no response"]
    out: list[str] = []
    for ep in data.get("entry_points", []) or []:
        addr = ep.get("address")
        name = ep.get("name") or "(unknown)"
        out.append(f"{addr}\t{name}")
    return out


@scoped_tool()
def retype_variable(function_name: str, variable_name: str, type_str: str) -> str:
    """
    Retype a variable in a function.
    """
    data = get_json(
        "retypeVariable",
        {
            "functionName": function_name,
            "variableName": variable_name,
            "type": type_str,
        },
        timeout=None,
    )
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and "status" in data:
        return data["status"]
    if isinstance(data, dict) and "error" in data:
        return f"Error: {data['error']}"
    return str(data)


@scoped_tool()
def rename_single_variable(function_name: str, variable_name: str, new_name: str) -> str:
    """
    Rename a variable in a function.
    """
    data = get_json(
        "renameVariable",
        {
            "functionName": function_name,
            "variableName": variable_name,
            "newName": new_name,
        },
        timeout=None,
    )
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and "status" in data:
        return data["status"]
    if isinstance(data, dict) and "error" in data:
        return f"Error: {data['error']}"
    return str(data)


@scoped_tool()
def rename_multi_variables(
    function_identifier: str,
    mapping_json: str = "",
    pairs: str = "",
    renames_json: str = "",
) -> str:
    """
    Rename multiple local variables in one call.
    - function_identifier: function name or address (hex)
    - Provide either mapping_json (JSON object old->new), renames_json (JSON array of {old,new}), or pairs ("old1:new1,old2:new2").
    Returns per-item results and totals.
    """
    params: dict[str, object] = {}
    ident = (function_identifier or "").strip()
    if ident.lower().startswith("0x") or ident.isdigit():
        params["address"] = ident
    else:
        params["functionName"] = ident

    import json as _json

    if renames_json:
        try:
            _json.loads(renames_json)
        except Exception:
            return "Error: renames_json is not valid JSON"
        params["renames"] = renames_json
    elif mapping_json:
        try:
            _json.loads(mapping_json)
        except Exception:
            return "Error: mapping_json is not valid JSON"
        params["mapping"] = mapping_json
    elif pairs:
        params["pairs"] = pairs
    else:
        return "Error: provide mapping_json, renames_json, or pairs"

    data = get_json("renameVariables", params, timeout=None)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        return f"Error: {data['error']}"
    try:
        total = data.get("total")
        renamed = data.get("renamed")
        return f"Batch rename: {renamed}/{total} applied"
    except Exception:
        return str(data)


@scoped_tool()
def define_types(c_code: str) -> str:
    """
    Define types from a C code string.
    """
    data = get_json("defineTypes", {"cCode": c_code}, timeout=None)
    if not data:
        return "Error: no response"
    # Expect a list of defined type names or a dict; normalize to string
    if isinstance(data, dict) and "error" in data:
        return f"Error: {data['error']}"
    if isinstance(data, (list, tuple)):
        return "Defined types: " + ", ".join(map(str, data))
    return str(data)


@scoped_tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})


@scoped_tool()
def hexdump_address(address: str, length: int = -1) -> str:
    """
    Hexdump data starting at an address. When length < 0, reads the exact defined size if available.
    """
    params = {"address": address}
    if length is not None:
        params["length"] = length
    return get_text("hexdump", params, timeout=None)


@scoped_tool()
def hexdump_data(name_or_address: str, length: int = -1) -> str:
    """
    Hexdump a data symbol by name or address. When length < 0, reads the exact defined size if available.
    """
    ident = (name_or_address or "").strip()
    if ident.startswith("0x"):
        return hexdump_address(ident, length)
    return get_text("hexdumpByName", {"name": ident, "length": length}, timeout=None)


@scoped_tool()
def get_data_decl(name_or_address: str, length: int = -1) -> str:
    """
    Return a declaration-like string and a hexdump for a data symbol by name or address.
    LLM-friendly: includes both a C-like declaration (when possible) and text hexdump.
    """
    ident = (name_or_address or "").strip()
    params = {"name": ident} if not ident.startswith("0x") else {"address": ident}
    if length is not None:
        params["length"] = length
    data = get_json("getDataDecl", params, timeout=None)
    if not data:
        return "Error: no response"
    if "error" in data:
        return f"Error: {data.get('error')}"
    decl = data.get("decl") or "(no declaration)"
    hexdump = data.get("hexdump") or ""
    addr = data.get("address", "")
    name = data.get("name", ident)
    return f"Declaration ({addr} {name}):\n{decl}\n\nHexdump:\n{hexdump}"


@scoped_tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("decompile", {"name": name}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "decompiled" in data:
        return file_line + data["decompiled"]
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    return file_line + str(data)


@scoped_tool()
def get_il(name_or_address: str, view: str = "hlil", ssa: bool = False) -> str:
    """
    Get IL for a function in the selected view.
    - view: one of hlil, mlil, llil
    - ssa: set True to request SSA form (MLIL/LLIL only)
    """
    file_line = f"File: {_active_filename()}\n\n"
    ident = (name_or_address or "").strip()
    params = {"view": view, "ssa": int(bool(ssa))}
    if ident.lower().startswith("0x") or ident.isdigit():
        params["address"] = ident
    else:
        params["name"] = ident
    data = get_json("il", params, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "il" in data:
        return file_line + data["il"]
    if "error" in data:
        import json as _json

        return file_line + _json.dumps(data, indent=2, ensure_ascii=False)
    return file_line + str(data)


@scoped_tool()
def fetch_disassembly(name: str) -> str:
    """
    Retrive the disassembled code of a function with a given name as assemby mnemonic instructions.
    """
    file_line = f"File: {_active_filename()}\n\n"
    data = get_json("assembly", {"name": name}, timeout=None)
    if not data:
        return file_line + "Error: no response"
    if "assembly" in data:
        return file_line + data["assembly"]
    if "error" in data:
        return file_line + f"Error: {data.get('error')}"
    return file_line + str(data)


@scoped_tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    The configured prefix (default "mcp_") will be automatically prepended if not present.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})


@scoped_tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})


@scoped_tool()
def set_comment(address: str, comment: str) -> str:
    """
    Set a comment at a specific address.
    """
    return safe_post("comment", {"address": address, "comment": comment})


@scoped_tool()
def set_function_comment(function_name: str, comment: str) -> str:
    """
    Set a comment for a function.
    """
    return safe_post("comment/function", {"name": function_name, "comment": comment})


@scoped_tool()
def get_comment(address: str) -> str:
    """
    Get the comment at a specific address.
    """
    return safe_get("comment", {"address": address})[0]


@scoped_tool()
def get_function_comment(function_name: str) -> str:
    """
    Get the comment for a function.
    """
    return safe_get("comment/function", {"name": function_name})[0]


@scoped_tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})


@scoped_tool()
def list_sections(offset: int = 0, limit: int = 100) -> list:
    """
    List sections in the program with pagination.

    Returns one line per section with: start-end, size, name, and any semantics/type if available.
    """
    data = get_json("sections", {"offset": offset, "limit": limit})
    if not data or not isinstance(data, dict):
        return ["Error: no response"]
    if data.get("error"):
        return [f"Error: {data.get('error')}"]
    sections = data.get("sections", []) or []
    out: list[str] = [f"File: {_active_filename()}"]
    for s in sections:
        try:
            start = s.get("start") or ""
            end = s.get("end") or ""
            size = s.get("size")
            name = s.get("name") or "(unnamed)"
            sem = s.get("semantics") or s.get("type") or ""
            tail = f"\t{sem}" if sem else ""
            out.append(f"{start}-{end}\t{size}\t{name}{tail}")
        except Exception:
            continue
    return out


@scoped_tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})


@scoped_tool()
def list_strings(offset: int = 0, count: int = 100) -> list:
    """
    List all strings in the database (paginated).
    """
    return safe_get("strings", {"offset": offset, "limit": count}, timeout=None)


@scoped_tool()
def list_strings_filter(offset: int = 0, count: int = 100, filter: str = "") -> list:
    """
    List matching strings in the database (paginated, filtered).
    """
    return safe_get(
        "strings/filter",
        {"offset": offset, "limit": count, "filter": filter},
        timeout=None,
    )


@scoped_tool()
def list_local_types(offset: int = 0, count: int = 200, include_libraries: bool = False) -> list:
    """
    List all local types in the database (paginated).
    """
    return safe_get(
        "localTypes",
        {
            "offset": offset,
            "limit": count,
            "includeLibraries": int(bool(include_libraries)),
        },
        timeout=None,
    )


@scoped_tool()
def search_types(
    query: str, offset: int = 0, count: int = 200, include_libraries: bool = False
) -> list:
    """
    Search local types whose name or declaration contains the substring.
    """
    return safe_get(
        "searchTypes",
        {
            "query": query,
            "offset": offset,
            "limit": count,
            "includeLibraries": int(bool(include_libraries)),
        },
        timeout=None,
    )


@scoped_tool()
def list_all_strings(batch_size: int = 500) -> list:
    """
    List all strings in the database (aggregated across pages).
    """
    results: list[str] = []
    offset = 0
    while True:
        data = get_json("strings", {"offset": offset, "limit": batch_size}, timeout=None)
        if not data or "strings" not in data:
            break
        items = data.get("strings", [])
        if not items:
            break
        for s in items:
            addr = s.get("address")
            length = s.get("length")
            stype = s.get("type")
            value = s.get("value")
            results.append(f"{addr}\t{length}\t{stype}\t{value}")
        if len(items) < batch_size:
            break
        offset += batch_size
    return results


@scoped_tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})


@scoped_tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})


@scoped_tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})


@scoped_tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})


@scoped_tool()
def get_binary_status() -> str:
    """
    Get the current status of the loaded binary.
    """
    return safe_get("status")[0]


@scoped_tool()
def open_binary(
    filepath: str,
    analysis_mode: str = "basic",
    platform: str = "",
    image_base: str = "",
) -> str:
    """Open a binary promptly and start background Binary Ninja analysis.

    Adjacent JSON metadata containing ``base`` is used automatically. Optional
    platform/image_base values override loader auto-detection.
    """
    try:
        payload = {
            "filepath": filepath,
            "analysis_mode": analysis_mode,
            "platform": platform,
            "image_base": image_base,
        }
        response = _request(
            "post",
            "load",
            retry_safe=True,
            json=payload,
            timeout=_effective_timeout("load", None),
        )
        try:
            data = response.json()
        except Exception:
            data = None
        if response.ok and isinstance(data, dict):
            message = data.get("message") or f"Binary loaded: {filepath}"
            selector = data.get("view_selector") or (
                f"view:{data['view_id']}" if data.get("view_id") else None
            )
            filename = data.get("filename")
            if selector or filename:
                message += (
                    f"\nStable selector: {selector or filename}\nFull path: {filename or filepath}"
                )
            return message
        if isinstance(data, dict) and data.get("error"):
            return f"Error: {data['error']}"
        return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as exc:
        return f"Request failed: {exc}"


@scoped_tool()
def close_binary(view: str, discard: bool = False) -> str:
    """Release one headless BinaryView and its native analysis memory.

    Use a stable view:N selector or absolute path. Modified views are protected
    unless discard is explicitly true.
    """
    try:
        response = _request(
            "post",
            "close",
            retry_safe=False,
            json={"view": view, "discard": discard},
            timeout=_effective_timeout("close", None),
        )
        try:
            data = response.json()
        except Exception:
            data = None
        if response.ok and isinstance(data, dict):
            return str(data.get("message") or f"Binary closed: {view}")
        if isinstance(data, dict) and data.get("error"):
            return f"Error: {data['error']}"
        return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as exc:
        return f"Request failed: {exc}"


@scoped_tool()
def list_binaries() -> list:
    """
    List managed/open binaries known to the server with ids and active flag.
    """
    data = get_json("binaries")
    if not data:
        return ["Error: no response"]
    if isinstance(data, dict) and data.get("error"):
        return [data.get("error")]
    items = data.get("binaries", [])
    out = []
    for it in items:
        vid = it.get("id")
        view_id = it.get("view_id")
        view_selector = it.get("view_selector") or (f"view:{view_id}" if view_id else "")
        fn = it.get("filename")
        basename = it.get("basename") or ""
        selectors = it.get("selectors") or []
        active = it.get("active")
        label = basename or fn or "(unknown)"
        full = fn or "(no filename)"
        selector_text = ", ".join(str(s) for s in selectors if s)
        mark = " *active*" if active else ""
        view_part = f" {view_selector}" if view_selector else ""
        out.append(
            f"{vid}. {label}{view_part}{mark}\n    path: {full}\n    selectors: {selector_text}"
        )
    return out


@scoped_tool()
def select_binary(view: str) -> str:
    """
    Select by view:N, ordinal:N, full path, or an unambiguous basename.
    This changes the legacy/GUI active view; still pass binary on later calls
    whenever more than one view is open.
    """
    data = get_json("selectBinary", {"view": view})
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        import json as _json

        return _json.dumps(data, indent=2, ensure_ascii=False)
    sel = data.get("selected") if isinstance(data, dict) else None
    if sel:
        ordinal = sel.get("id") or "?"
        view_id = sel.get("view_id") or ""
        fn = sel.get("filename") or ""
        basename = sel.get("basename") or ""
        selectors = sel.get("selectors") or []
        selector_text = ", ".join(str(s) for s in selectors if s)
        display_name = basename or fn or "(unknown)"
        view_part = f" (view:{view_id})" if view_id else ""
        path_part = f"\nFull path: {fn}" if fn else ""
        return (
            f"Selected {ordinal}: {display_name}{view_part}{path_part}\nSelectors: {selector_text}"
        )
    return str(data)


@scoped_tool()
def delete_comment(address: str) -> str:
    """
    Delete the comment at a specific address.
    """
    return safe_delete("comment", {"address": address})


@scoped_tool()
def delete_function_comment(function_name: str) -> str:
    """
    Delete the comment for a function.
    """
    return safe_delete("comment/function", {"name": function_name})


@scoped_tool()
def function_at(address: str) -> str:
    """
    Retrive the name of the function the address belongs to. Address must be in hexadecimal format 0x00001
    """
    return "\n".join(safe_get("functionAt", {"address": address}))


@scoped_tool()
def get_user_defined_type(type_name: str) -> str:
    """
    Retrive definition of a user defined type (struct, enumeration, typedef, union)
    """
    return "\n".join(safe_get("getUserDefinedType", {"name": type_name}))


@scoped_tool()
def get_xrefs_to(address: str) -> list:
    """
    Get all cross references (code and data) to the given address.
    Address can be hex (e.g., 0x401000) or decimal.
    """
    return safe_get("getXrefsTo", {"address": address})


@scoped_tool()
def get_xrefs_to_field(struct_name: str, field_name: str) -> list:
    """
    Get all cross references to a named struct field (member).
    """
    return safe_get("getXrefsToField", {"struct": struct_name, "field": field_name})


@scoped_tool()
def get_xrefs_to_struct(struct_name: str) -> list:
    """
    Get cross references/usages related to a struct name.
    """
    return safe_get("getXrefsToStruct", {"name": struct_name})


@scoped_tool()
def get_xrefs_to_type(type_name: str) -> list:
    """
    Get xrefs/usages related to a struct or type name.
    Includes global instances, code refs to those, HLIL matches, and functions whose signature mentions the type.
    """
    return safe_get("getXrefsToType", {"name": type_name})


@scoped_tool()
def get_xrefs_to_enum(enum_name: str) -> list:
    """
    Get usages/xrefs of an enum by scanning for member values and matches.
    """
    return safe_get("getXrefsToEnum", {"name": enum_name})


@scoped_tool()
def get_xrefs_to_union(union_name: str) -> list:
    """
    Get cross references/usages related to a union type by name.
    """
    return safe_get("getXrefsToUnion", {"name": union_name})


@scoped_tool()
def get_stack_frame_vars(function_identifier: str) -> list:
    """
    Get stack frame variable information for a function by name or address.
    Returns names, offsets, sizes, and types of local variables.
    """
    ident = (function_identifier or "").strip()
    params = {}
    # Choose param name based on identifier format
    if ident.lower().startswith("0x") or ident.isdigit():
        params["address"] = ident
    else:
        params["name"] = ident
    data = get_json("getStackFrameVars", params)
    if not data:
        return []
    if isinstance(data, dict) and data.get("error"):
        return []
    if isinstance(data, dict) and data.get("stack_frame_vars"):
        return data["stack_frame_vars"]
    return []


@scoped_tool()
def format_value(address: str, text: str, size: int = 0) -> list:
    """
    Convert and annotate a value at an address in Binary Ninja.
    Adds a comment with hex/dec and C literal/string so you can see the change.
    """
    return safe_get("formatValue", {"address": address, "text": text, "size": size}, timeout=None)


@scoped_tool()
def convert_number(text: str, size: int = 0) -> str:
    """
    Convert a number or string to multiple representations (hex/dec/bin, LE/BE, C char/string literals).
    Accepts decimal (e.g., 123), hex (0x7b or 7Bh), binary (0b1111011), octal (0o173),
    char ('A'), or string ("ABC" with escapes like \x41).
    """
    data = get_json("convertNumber", {"text": text, "size": size}, timeout=None)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        return f"Error: {data['error']}"
    import json as _json

    return _json.dumps(data, indent=2, ensure_ascii=False)


@scoped_tool()
def get_type_info(type_name: str) -> str:
    """
    Resolve a type name and return its declaration and details (kind, members, enum values).
    """
    data = get_json("getTypeInfo", {"name": type_name}, timeout=None)
    if not data:
        return "Error: no response"
    if "error" in data:
        return f"Error: {data.get('error')}"
    import json as _json

    return _json.dumps(data, indent=2, ensure_ascii=False)


def _normalize_identifier_input(value: str | list[str]) -> list[str]:
    tokens: list[str] = []
    if isinstance(value, str):
        raw = value.replace(";", ",").split(",")
        tokens.extend([tok.strip() for tok in raw if tok.strip()])
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            if item is None:
                continue
            tokens.extend(_normalize_identifier_input(str(item)))
    return tokens


@scoped_tool()
def get_callers(identifiers: str) -> str:
    """
    List callers and caller sites for one or more function identifiers (name or address).
    Provide comma-separated identifiers like "sub_401000,main".
    """
    items = _normalize_identifier_input(identifiers)
    if not items:
        return "Error: provide at least one identifier"
    data = get_json("getCallers", {"identifiers": ",".join(items)}, timeout=None)
    if not data:
        return "Error: no response"
    import json as _json

    return _json.dumps(data, indent=2, ensure_ascii=False)


@scoped_tool()
def get_callees(identifiers: str) -> str:
    """
    List callees and call sites for one or more function identifiers (name or address).
    Provide comma-separated identifiers like "sub_401000,main".
    """
    items = _normalize_identifier_input(identifiers)
    if not items:
        return "Error: provide at least one identifier"
    data = get_json("getCallees", {"identifiers": ",".join(items)}, timeout=None)
    if not data:
        return "Error: no response"
    import json as _json

    return _json.dumps(data, indent=2, ensure_ascii=False)


@scoped_tool()
def set_function_prototype(name_or_address: str, prototype: str) -> str:
    """
    Set a function's prototype by name or address.
    """
    # Use GET like other endpoints (server accepts complex prototypes)
    ident = (name_or_address or "").strip()
    params = {"prototype": prototype}
    # Choose param name based on identifier format
    if ident.lower().startswith("0x") or ident.isdigit():
        params["address"] = ident
    else:
        params["name"] = ident
    data = get_json("setFunctionPrototype", params, timeout=None)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and "status" in data:
        return f"Applied prototype at {data.get('address')}: {data.get('applied_type')}"
    if isinstance(data, dict) and "error" in data:
        return f"Error: {data['error']}"
    return str(data)


@scoped_tool()
def make_function_at(address: str, platform: str = "") -> str:
    """
    Create a function at the given address. Platform is optional (e.g., "linux-x86_64").
    Use "default" to explicitly select the BinaryView/platform default.
    Returns status and function info; no-op if the function already exists.
    """
    params = {"address": address}
    if platform:
        params["platform"] = platform
    data = get_json("makeFunctionAt", params, timeout=None)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        import json as _json

        return _json.dumps(data, indent=2, ensure_ascii=False)
    if isinstance(data, dict) and data.get("status") == "exists":
        return f"Function already exists at {data.get('address')}: {data.get('name')}"
    if isinstance(data, dict) and data.get("status") == "ok":
        return f"Created function at {data.get('address')}: {data.get('name')}"
    return str(data)


@scoped_tool()
def list_platforms() -> str:
    """
    List all available platform names from Binary Ninja.
    """
    data = get_json("platforms")
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("error"):
        import json as _json

        return _json.dumps(data, indent=2, ensure_ascii=False)
    plats = data.get("platforms") if isinstance(data, dict) else None
    if not plats:
        return "(no platforms)"
    return "\n".join(plats)


@scoped_tool()
def declare_c_type(c_declaration: str) -> str:
    """
    Create or update a local type from a C declaration.
    """
    data = get_json("declareCType", {"declaration": c_declaration}, timeout=None)
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("defined_types"):
        names = ", ".join(data["defined_types"].keys())
        return f"Declared types ({data.get('count', 0)}): {names}"
    if isinstance(data, dict) and "error" in data:
        return f"Error: {data['error']}"
    return str(data)


@scoped_tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    data = get_json(
        "setLocalVariableType",
        {
            "functionAddress": function_address,
            "variableName": variable_name,
            "newType": new_type,
        },
        timeout=None,
    )
    if not data:
        return "Error: no response"
    if isinstance(data, dict) and data.get("status") == "ok":
        return f"Retyped {data.get('variable')} in {data.get('function')} to {data.get('applied_type')}"
    if isinstance(data, dict) and "error" in data:
        return f"Error: {data['error']}"
    return str(data)


@scoped_tool()
def patch_bytes(address: str, data: str, save_to_file: bool = True) -> str:
    """
    Patch bytes at a given address in the binary.
    - address: Address to patch (hex string like "0x401000" or decimal)
    - data: Hex string of bytes to write (e.g., "90 90" or "9090" or "0x90 0x90")
    - save_to_file: If True (default), save patched binary to disk and re-sign on macOS.
                    If False, only modify in memory without affecting the original file.

    Returns status with original and patched bytes.
    On macOS, automatically re-signs the binary after patching to avoid execution errors.
    """
    # Handle boolean type conversion (MCP may pass as string)
    if isinstance(save_to_file, str):
        save_to_file = save_to_file.lower() not in ("false", "0", "no")

    params = {"address": address, "data": data, "save_to_file": save_to_file}
    result = get_json("patch", params, timeout=None)
    if not result:
        return "Error: no response"

    status = result.get("status") if isinstance(result, dict) else None
    if status in ("ok", "partial"):
        orig = result.get("original_bytes", "")
        patched = result.get("patched_bytes", "")
        written = result.get("bytes_written", 0)
        requested = result.get("bytes_requested", 0)
        addr = result.get("address", address)
        saved = result.get("saved_to_file", False)
        saved_path = result.get("saved_path", "")
        save_error = result.get("save_error", "")
        codesign = result.get("codesign", {})
        warning = result.get("warning", "")

        msg = f"Patched {written}/{requested} bytes at {addr}"
        if status == "partial":
            msg += " (PARTIAL WRITE)"
        if warning:
            msg += f"\nWarning: {warning}"
        if orig:
            msg += f"\nOriginal: {orig}"
        if patched:
            msg += f"\nPatched:  {patched}"
        if saved:
            msg += f"\nSaved to file: {saved_path}"
        elif save_error:
            msg += f"\nWarning: File not saved - {save_error}"

        # Show codesign status for macOS
        if codesign:
            if codesign.get("success"):
                msg += f"\nCode signing: {codesign.get('message', 'Re-signed successfully')}"
            elif codesign.get("attempted"):
                msg += f"\nCode signing: Failed - {codesign.get('error', 'Unknown error')}"

        return msg
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    return str(result)


if __name__ == "__main__":
    # Important: write any logs to stderr to avoid corrupting MCP stdio JSON-RPC
    print("Starting MCP bridge service...", file=_sys.stderr)
    try:
        _start_parent_watchdog()
        mcp.run()
    except Exception as _e:
        # Ensure any runtime exception is captured in the log file
        _bridge_excepthook(type(_e), _e, _e.__traceback__)
        raise
