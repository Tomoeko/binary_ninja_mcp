"""Shared helpers for the Binary Ninja 6 native-MCP compatibility layer.

The native MCP server represents addresses as hexadecimal strings and reports
domain errors separately from transport errors.  These helpers keep that
contract independent from the HTTP or stdio front end that invokes it.
"""

from __future__ import annotations

import base64
import math
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from enum import Enum


class NativeMcpError(RuntimeError):
    """A stable, serializable error raised by native-style MCP operations."""

    def __init__(self, code: str, message: str, details: object | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"code": self.code, "message": self.message}
        if self.details is not None:
            result["details"] = json_safe(self.details)
        return result


def hex_address(value: object) -> str:
    """Return an integer-like value using Binary Ninja's address convention."""

    if isinstance(value, bool):
        raise NativeMcpError("invalid_params", "Address must be an integer, not a boolean")
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError) as exc:
        raise NativeMcpError(
            "invalid_params", "Address is not an integer", {"value": value}
        ) from exc
    if number < 0:
        raise NativeMcpError("invalid_params", "Address must not be negative", {"value": value})
    return hex(number)


def json_safe(value: object) -> object:
    """Recursively convert common Binary Ninja/Python values to JSON values."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, bytes):
        return {
            "encoding": "base64",
            "data": base64.b64encode(value).decode("ascii"),
        }
    if isinstance(value, Enum):
        return value.name
    if is_dataclass(value) and not isinstance(value, type):
        return json_safe(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return [json_safe(item) for item in sorted(value, key=str)]
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    return str(value)


def parse_integer(
    value: object,
    name: str = "value",
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """Parse a strict integer parameter and enforce optional inclusive bounds."""

    if isinstance(value, bool):
        raise NativeMcpError("invalid_params", f"Parameter '{name}' must be an integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise NativeMcpError("invalid_params", f"Parameter '{name}' must not be empty")
        try:
            if text.lower().startswith("0n"):
                result = int(text[2:], 10)
            else:
                result = int(text, 0)
        except ValueError as exc:
            raise NativeMcpError(
                "invalid_params",
                f"Parameter '{name}' must be an integer",
                {"value": value},
            ) from exc
    else:
        raise NativeMcpError(
            "invalid_params",
            f"Parameter '{name}' must be an integer",
            {"value": value},
        )
    if minimum is not None and result < minimum:
        raise NativeMcpError(
            "invalid_params",
            f"Parameter '{name}' must be at least {minimum}",
            {"value": result},
        )
    if maximum is not None and result > maximum:
        raise NativeMcpError(
            "invalid_params",
            f"Parameter '{name}' must be at most {maximum}",
            {"value": result},
        )
    return result


def parse_address(bv: object, value: object, name: str = "address") -> int:
    """Resolve an integer or Binary Ninja expression to a non-negative address."""

    if isinstance(value, bool):
        raise NativeMcpError("invalid_params", f"Parameter '{name}' must be an address expression")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.strip():
        expression = value.strip()
        parser = getattr(bv, "parse_expression", None)
        try:
            if callable(parser):
                result = int(parser(expression))
            elif expression.lower().startswith("0n"):
                result = int(expression[2:], 10)
            else:
                result = int(expression, 0)
        except Exception as exc:
            raise NativeMcpError(
                "invalid_address",
                f"Could not resolve parameter '{name}' as a Binary Ninja expression",
                {"expression": value},
            ) from exc
    else:
        raise NativeMcpError(
            "invalid_params",
            f"Parameter '{name}' must be an address expression string",
            {"value": value},
        )
    if result < 0 or result > 0xFFFFFFFFFFFFFFFF:
        raise NativeMcpError(
            "invalid_address",
            f"Parameter '{name}' is outside the 64-bit address range",
            {"value": result},
        )
    return result


def resolve_function(bv: object, address: object, arch: str | None = None) -> object:
    """Resolve an expression to exactly one function starting at that address."""

    start = parse_address(bv, address, "function")
    getter = getattr(bv, "get_functions_at", None)
    functions = list(getter(start)) if callable(getter) else []
    if not functions:
        single_getter = getattr(bv, "get_function_at", None)
        function = single_getter(start) if callable(single_getter) else None
        if function is not None:
            functions = [function]
    if arch is not None:
        if not isinstance(arch, str) or not arch:
            raise NativeMcpError("invalid_params", "Parameter 'arch' must be a non-empty string")
        functions = [
            function
            for function in functions
            if getattr(getattr(function, "arch", None), "name", None) == arch
        ]
    if not functions:
        raise NativeMcpError(
            "function_not_found",
            "No matching function was found",
            {"function": hex(start), "arch": arch},
        )
    if len(functions) != 1:
        raise NativeMcpError(
            "ambiguous_function",
            "Multiple matching functions were found",
            {
                "function": hex(start),
                "architectures": [
                    getattr(getattr(function, "arch", None), "name", None) for function in functions
                ],
            },
        )
    return functions[0]


def resolve_type(bv: object, value: object, name: str = "type") -> object:
    """Resolve a named type in a BinaryView."""

    if not isinstance(value, str) or not value:
        raise NativeMcpError("invalid_params", f"Parameter '{name}' must be a non-empty string")
    getter = getattr(bv, "get_type_by_name", None)
    result = getter(value) if callable(getter) else None
    if result is None:
        raise NativeMcpError("type_not_found", "No matching type was found", {"type": value})
    return result


def paginate(
    items: Iterable[object],
    args: Mapping[str, object],
    *,
    default_limit: int = 100,
    max_limit: int = 1000,
    item_key: str = "items",
) -> dict[str, object]:
    """Materialize, paginate, and annotate a native-style result collection."""

    offset = parse_integer(args.get("offset", 0), "offset", minimum=0)
    limit = parse_integer(args.get("limit", default_limit), "limit", minimum=0, maximum=max_limit)
    materialized = list(items)
    total = len(materialized)
    page = materialized[offset : offset + limit]
    more = offset + len(page) < total
    next_offset = offset + len(page) if more and page else None
    return {
        item_key: json_safe(page),
        "offset": offset,
        "limit": limit,
        "count": len(page),
        "total": total,
        "nextOffset": next_offset,
        "truncated": more,
    }


def maybe_analysis_update(
    bv: object,
    args: Mapping[str, object],
    *,
    wait: bool = False,
) -> None:
    """Request post-mutation analysis unless a native batching flag skips it."""

    skip = args.get("skipAnalysisUpdate", False)
    if not isinstance(skip, bool):
        raise NativeMcpError("invalid_params", "Parameter 'skipAnalysisUpdate' must be a boolean")
    if skip:
        return
    method_name = "update_analysis_and_wait" if wait else "update_analysis"
    method = getattr(bv, method_name, None)
    if not callable(method):
        raise NativeMcpError("unsupported_api", f"BinaryView does not support {method_name}")
    method()


@contextmanager
def undo_transaction(bv: object, args: Mapping[str, object], label: str):
    """Run a mutation in a BinaryView undo transaction when the API is available."""

    enabled = args.get("undo", True)
    if not isinstance(enabled, bool):
        raise NativeMcpError("invalid_params", "Parameter 'undo' must be a boolean")
    factory = getattr(bv, "undoable_transaction", None)
    if enabled and callable(factory):
        with factory():
            yield
    else:
        yield


__all__ = [
    "NativeMcpError",
    "hex_address",
    "json_safe",
    "maybe_analysis_update",
    "paginate",
    "parse_address",
    "parse_integer",
    "resolve_function",
    "resolve_type",
    "undo_transaction",
]
