"""Binary Ninja 6 native-style inspection and analysis operations.

This module intentionally has no transport dependencies.  A headless host can
pass the currently selected ``BinaryView`` to :func:`dispatch_inspection` and
serialize the returned Python object directly as JSON.
"""

from __future__ import annotations

import base64
import math
import os
import time
from collections.abc import Callable, Iterable, Mapping

from .native_mcp_common import (
    NativeMcpError,
    hex_address,
    json_safe,
    paginate,
    parse_address,
    parse_integer,
    resolve_function,
    resolve_type,
)

_STRING_SCAN_CHUNK_BYTES = 1024 * 1024
_STRING_QUERY_SAMPLE_BYTES = 4096
_DEFAULT_FUNCTION_ANALYSIS_TIMEOUT_SEC = 1740.0


def _attr(value: object, name: str, default: object = None) -> object:
    try:
        return getattr(value, name, default)
    except Exception:
        return default


def _enum_name(value: object) -> str | None:
    if value is None:
        return None
    name = _attr(value, "name")
    return str(name) if name is not None else str(value)


def _required(args: Mapping[str, object], name: str) -> object:
    if name not in args:
        raise NativeMcpError("invalid_params", f"Missing required parameter '{name}'")
    return args[name]


def _string(args: Mapping[str, object], name: str, *, required: bool = False) -> str | None:
    if name not in args:
        if required:
            raise NativeMcpError("invalid_params", f"Missing required parameter '{name}'")
        return None
    value = args[name]
    if not isinstance(value, str):
        raise NativeMcpError("invalid_params", f"Parameter '{name}' must be a string")
    return value


def _boolean(args: Mapping[str, object], name: str, default: bool) -> bool:
    value = args.get(name, default)
    if not isinstance(value, bool):
        raise NativeMcpError("invalid_params", f"Parameter '{name}' must be a boolean")
    return value


def _string_array(args: Mapping[str, object], name: str) -> list[str]:
    value = args.get(name, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise NativeMcpError("invalid_params", f"Parameter '{name}' must be an array of strings")
    return value


def _function(args: Mapping[str, object], bv: object) -> object:
    arch = _string(args, "arch")
    return resolve_function(bv, _required(args, "function"), arch or None)


def _as_address(value: object | None) -> str | None:
    if value is None:
        return None
    try:
        return hex_address(value)
    except NativeMcpError:
        return None


def _type_text(value: object) -> str | None:
    return None if value is None else str(value)


def _symbol_record(symbol: object) -> dict[str, object]:
    namespace = _attr(symbol, "namespace")
    return {
        "name": _attr(symbol, "name"),
        "shortName": _attr(symbol, "short_name", _attr(symbol, "name")),
        "fullName": _attr(symbol, "full_name", _attr(symbol, "name")),
        "rawName": _attr(symbol, "raw_name", _attr(symbol, "name")),
        "address": _as_address(_attr(symbol, "address")),
        "type": _enum_name(_attr(symbol, "type")),
        "binding": _enum_name(_attr(symbol, "binding")),
        "namespace": str(namespace) if namespace is not None else None,
        "ordinal": _attr(symbol, "ordinal"),
        "autoDefined": bool(_attr(symbol, "auto", _attr(symbol, "auto_defined", False))),
    }


def _function_record(function: object) -> dict[str, object]:
    symbol = _attr(function, "symbol")
    blocks = list(_attr(function, "basic_blocks", []) or [])
    ranges = []
    for item in _attr(function, "address_ranges", []) or []:
        start = _attr(item, "start")
        end = _attr(item, "end")
        if start is not None and end is not None:
            ranges.append({"start": hex_address(start), "end": hex_address(end)})
    start = _attr(function, "start")
    lowest = _attr(function, "lowest_address", start)
    highest = _attr(function, "highest_address", start)
    return {
        "name": _attr(function, "name"),
        "shortName": _attr(symbol, "short_name", _attr(function, "name")),
        "fullName": _attr(symbol, "full_name", _attr(function, "name")),
        "rawName": _attr(symbol, "raw_name", _attr(function, "name")),
        "address": _as_address(start),
        "arch": _attr(_attr(function, "arch"), "name"),
        "platform": _attr(_attr(function, "platform"), "name"),
        "lowestAddress": _as_address(lowest),
        "highestAddress": _as_address(highest),
        "basicBlockCount": len(blocks),
        "ranges": ranges,
        "hasUserAnnotations": bool(_attr(function, "has_user_annotations", False)),
        "needsUpdate": bool(_attr(function, "needs_update", False)),
        "analysisSkipped": bool(_attr(function, "analysis_skipped", False)),
        "analysisSkipReason": _enum_name(_attr(function, "analysis_skip_reason")),
    }


def _reference_record(reference: object) -> dict[str, object]:
    function = _attr(reference, "function")
    return {
        "address": _as_address(_attr(reference, "address")),
        "arch": _attr(_attr(reference, "arch"), "name"),
        "function": _as_address(_attr(function, "start")),
        "functionName": _attr(function, "name"),
    }


def _variable_record(variable: object, parameters: set[object] | None = None) -> dict[str, object]:
    identifier = _attr(variable, "identifier")
    return {
        "name": _attr(variable, "name"),
        "type": _type_text(_attr(variable, "type")),
        "sourceType": _enum_name(_attr(variable, "source_type")),
        "index": _attr(variable, "index"),
        "storage": _attr(variable, "storage"),
        "identifier": str(identifier) if identifier is not None else None,
        "parameter": variable in parameters if parameters is not None else False,
    }


def _iter_symbols(bv: object) -> list[object]:
    getter = _attr(bv, "get_symbols")
    if callable(getter):
        return list(getter())
    mapping = _attr(bv, "symbols", {}) or {}
    if isinstance(mapping, Mapping):
        result = []
        for values in mapping.values():
            if isinstance(values, (list, tuple, set)):
                result.extend(values)
            else:
                result.append(values)
        return result
    return list(mapping)


def _address_bounds(args: Mapping[str, object], bv: object) -> tuple[int, int] | None:
    address_present = "address" in args
    start_present = "start" in args
    if address_present and start_present:
        raise NativeMcpError("invalid_params", "Specify 'address' or 'start', not both")
    if "end" in args and "length" in args:
        raise NativeMcpError(
            "invalid_params", "Parameters 'end' and 'length' are mutually exclusive"
        )
    if not address_present and not start_present:
        if "end" in args or "length" in args:
            raise NativeMcpError("invalid_params", "A range requires 'address' or 'start'")
        return None
    start_name = "address" if address_present else "start"
    start = parse_address(bv, args[start_name], start_name)
    if "length" in args:
        length = parse_address(bv, args["length"], "length")
        end = start + length
    elif "end" in args:
        end = parse_address(bv, args["end"], "end")
    else:
        end = start + 1
    if end < start or end > 0x10000000000000000:
        raise NativeMcpError("invalid_address", "Address range overflows 64 bits")
    return start, end


def _filter_records(
    records: Iterable[dict[str, object]],
    args: Mapping[str, object],
    bv: object,
) -> list[dict[str, object]]:
    bounds = _address_bounds(args, bv)
    query = _string(args, "query")
    lowered = query.casefold() if query else None
    result = []
    for record in records:
        if bounds is not None:
            record_start = record.get("address", record.get("start"))
            if not isinstance(record_start, str):
                continue
            try:
                item_start = int(record_start, 16)
                record_end = record.get("end")
                item_end = int(record_end, 16) if isinstance(record_end, str) else item_start + 1
            except ValueError:
                continue
            if item_end <= bounds[0] or item_start >= bounds[1]:
                continue
        if lowered is not None:
            searchable = " ".join(str(value) for value in record.values() if value is not None)
            if lowered not in searchable.casefold():
                continue
        result.append(record)
    return result


def _sort_records(records: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    def key(record: dict[str, object]):
        address = record.get("address", record.get("start"))
        try:
            numeric = int(str(address), 16)
        except (TypeError, ValueError):
            numeric = 0x10000000000000000
        return numeric, str(record.get("name", ""))

    return sorted(records, key=key)


def _filter_and_sort_symbol_records(
    records: Iterable[dict[str, object]],
    args: Mapping[str, object],
    bv: object,
) -> list[dict[str, object]]:
    range_args = {key: value for key, value in args.items() if key != "query"}
    filtered = _filter_records(records, range_args, bv)
    query = _string(args, "query")
    if query:
        lowered = query.casefold()
        filtered = [
            record
            for record in filtered
            if any(
                lowered in str(record.get(field) or "").casefold()
                for field in ("name", "shortName", "fullName", "rawName")
            )
        ]

    def key(record: dict[str, object]) -> tuple[int, str]:
        try:
            address = int(str(record.get("address")), 16)
        except (TypeError, ValueError):
            address = 0x10000000000000000
        return address, str(record.get("fullName") or "")

    return sorted(filtered, key=key)


def _analysis_status(_args: Mapping[str, object], bv: object) -> dict[str, object]:
    info = _attr(bv, "analysis_info")
    progress = _attr(bv, "analysis_progress")
    active = []
    for entry in _attr(info, "active_info", []) or []:
        function = _attr(entry, "func")
        active.append(
            {
                "function": _as_address(_attr(function, "start")),
                "name": _attr(function, "name"),
                "analysisTime": _attr(entry, "analysis_time", 0),
                "updateCount": _attr(entry, "update_count", 0),
                "submitCount": _attr(entry, "submit_count", 0),
            }
        )
    state = _enum_name(_attr(info, "state", _attr(bv, "analysis_state")))
    return {
        "state": state,
        "analysisTime": _attr(info, "analysis_time", 0),
        "progress": {
            "state": _enum_name(_attr(progress, "state")),
            "count": _attr(progress, "count", 0),
            "total": _attr(progress, "total", 0),
        },
        "active": active,
        "aborted": bool(_attr(bv, "analysis_is_aborted", False)),
    }


def _analysis_update(args: Mapping[str, object], bv: object) -> dict[str, object]:
    method = _attr(bv, "update_analysis")
    if not callable(method):
        raise NativeMcpError("unsupported_api", "BinaryView does not support update_analysis")
    method()
    return {"started": True, "analysis": _analysis_status(args, bv)}


def _analysis_update_and_wait(args: Mapping[str, object], bv: object) -> dict[str, object]:
    method = _attr(bv, "update_analysis_and_wait")
    if not callable(method):
        raise NativeMcpError(
            "unsupported_api", "BinaryView does not support update_analysis_and_wait"
        )
    method()
    return {"completed": True, "analysis": _analysis_status(args, bv)}


def _analysis_abort(args: Mapping[str, object], bv: object) -> dict[str, object]:
    method = _attr(bv, "abort_analysis")
    if not callable(method):
        raise NativeMcpError("unsupported_api", "BinaryView does not support abort_analysis")
    method()
    return {"aborted": True, "analysis": _analysis_status(args, bv)}


def _triage(_args: Mapping[str, object], bv: object) -> dict[str, object]:
    entry_function = _attr(bv, "entry_function")
    file_metadata = _attr(bv, "file")
    return {
        "binaryView": {
            "filename": _attr(file_metadata, "filename"),
            "viewType": _attr(bv, "view_type"),
            "start": _as_address(_attr(bv, "start")),
            "end": _as_address(_attr(bv, "end")),
            "length": _attr(bv, "length", None),
            "entryPoint": _as_address(_attr(bv, "entry_point", _attr(entry_function, "start"))),
            "architecture": _attr(_attr(bv, "arch"), "name"),
            "platform": _attr(_attr(bv, "platform"), "name"),
            "executable": bool(_attr(bv, "executable", False)),
            "relocatable": bool(_attr(bv, "relocatable", False)),
            "addressSize": _attr(bv, "address_size"),
        },
        "analysis": _analysis_status({}, bv),
        "segmentCount": len(_attr(bv, "segments", []) or []),
        "sectionCount": len(_attr(bv, "sections", {}) or {}),
        "symbolCount": len(_iter_symbols(bv)),
        "functionCount": len(_attr(bv, "functions", []) or []),
        "stringCount": len(_attr(bv, "strings", []) or []),
        "dataVariableCount": len(_attr(bv, "data_vars", {}) or {}),
    }


def _entry_points(args: Mapping[str, object], bv: object) -> dict[str, object]:
    functions = list(_attr(bv, "entry_functions", []) or [])
    if not functions:
        one = _attr(bv, "entry_function")
        if one is not None:
            functions.append(one)
    records = _sort_records(_function_record(function) for function in functions)
    return paginate(records, args, item_key="entryPoints")


def _segments(args: Mapping[str, object], bv: object) -> dict[str, object]:
    records = []
    for segment in _attr(bv, "segments", []) or []:
        info = _attr(segment, "segment_info")
        records.append(
            {
                "start": _as_address(_attr(segment, "start")),
                "end": _as_address(_attr(segment, "end")),
                "length": _attr(segment, "length"),
                "dataOffset": _as_address(_attr(segment, "data_offset")),
                "dataLength": _attr(segment, "data_length"),
                "dataEnd": _as_address(_attr(segment, "data_end")),
                "flags": _enum_name(_attr(info, "flags")),
                "readable": bool(_attr(segment, "readable", False)),
                "writable": bool(_attr(segment, "writable", False)),
                "executable": bool(_attr(segment, "executable", False)),
                "autoDefined": bool(_attr(segment, "auto_defined", False)),
            }
        )
    return paginate(_filter_records(_sort_records(records), args, bv), args, item_key="segments")


def _sections(args: Mapping[str, object], bv: object) -> dict[str, object]:
    sections = _attr(bv, "sections", {}) or {}
    values = sections.values() if isinstance(sections, Mapping) else sections
    records = []
    for section in values:
        records.append(
            {
                "name": _attr(section, "name"),
                "start": _as_address(_attr(section, "start")),
                "end": _as_address(_attr(section, "end")),
                "length": _attr(section, "length"),
                "semantics": _enum_name(_attr(section, "semantics")),
                "type": _attr(section, "type"),
                "align": _attr(section, "align"),
                "entrySize": _attr(section, "entry_size"),
                "linkedSection": _attr(section, "linked_section"),
                "infoSection": _attr(section, "info_section"),
                "infoData": _attr(section, "info_data"),
                "autoDefined": bool(_attr(section, "auto_defined", False)),
            }
        )
    return paginate(_filter_records(_sort_records(records), args, bv), args, item_key="sections")


def _symbols(args: Mapping[str, object], bv: object) -> dict[str, object]:
    records = [_symbol_record(symbol) for symbol in _iter_symbols(bv)]
    return paginate(_filter_and_sort_symbol_records(records, args, bv), args, item_key="symbols")


def _symbols_at(args: Mapping[str, object], bv: object) -> dict[str, object]:
    address = parse_address(bv, _required(args, "address"), "address")
    getter = _attr(bv, "get_symbols")
    if callable(getter):
        try:
            symbols = list(getter(address, 1))
        except TypeError:
            # Keep transport-free test doubles and older compatible SDK
            # shims usable while preferring Binary Ninja's bounded API.
            symbols = list(getter())
    else:
        symbols = _iter_symbols(bv)
    records = [
        _symbol_record(symbol) for symbol in symbols if int(_attr(symbol, "address", -1)) == address
    ]
    return {
        "address": hex_address(address),
        "symbols": _sort_records(records),
        "count": len(records),
    }


def _symbol_kind(symbol: object) -> str:
    return (_enum_name(_attr(symbol, "type")) or "").casefold()


_IMPORT_SYMBOL_KINDS = {
    "importaddresssymbol",
    "importedfunctionsymbol",
    "importeddatasymbol",
}
_EXPORT_SYMBOL_BINDINGS = {"globalbinding", "weakbinding"}


def _imports(args: Mapping[str, object], bv: object) -> dict[str, object]:
    records = [
        _symbol_record(symbol)
        for symbol in _iter_symbols(bv)
        if _symbol_kind(symbol) in _IMPORT_SYMBOL_KINDS
    ]
    return paginate(_filter_and_sort_symbol_records(records, args, bv), args, item_key="imports")


def _exports(args: Mapping[str, object], bv: object) -> dict[str, object]:
    records = [
        _symbol_record(symbol)
        for symbol in _iter_symbols(bv)
        if _symbol_kind(symbol) not in _IMPORT_SYMBOL_KINDS
        and (_enum_name(_attr(symbol, "binding")) or "").casefold() in _EXPORT_SYMBOL_BINDINGS
    ]
    return paginate(_filter_and_sort_symbol_records(records, args, bv), args, item_key="exports")


def _relocation_record(relocation: object) -> dict[str, object]:
    info = _attr(relocation, "info")
    symbol = _attr(relocation, "symbol")
    return {
        "address": _as_address(_attr(info, "address", _attr(relocation, "reloc"))),
        "target": _as_address(_attr(relocation, "target", _attr(info, "target"))),
        "symbolName": _attr(symbol, "full_name", _attr(symbol, "name")),
        "arch": _attr(_attr(relocation, "arch"), "name"),
        "type": _enum_name(_attr(info, "type")),
        "nativeType": _attr(info, "native_type"),
        "size": _attr(info, "size"),
        "addend": _attr(info, "addend"),
        "pcRelative": bool(_attr(info, "pc_relative", False)),
        "baseRelative": bool(_attr(info, "base_relative", False)),
        "external": bool(_attr(info, "external", False)),
        "dataRelocation": bool(_attr(info, "data_relocation", False)),
    }


def _relocations(args: Mapping[str, object], bv: object) -> dict[str, object]:
    direct = _attr(bv, "relocations")
    if direct is not None:
        relocations = list(direct)
    else:
        relocations = []
        getter = _attr(bv, "relocations_at")
        for start, _end in _attr(bv, "relocation_ranges", []) or []:
            if callable(getter):
                relocations.extend(getter(start))
    unique: dict[tuple[object, object, object], dict[str, object]] = {}
    for relocation in relocations:
        record = _relocation_record(relocation)
        key = (record["address"], record["target"], record["symbolName"])
        unique[key] = record
    records = _filter_records(_sort_records(unique.values()), args, bv)
    return paginate(records, args, item_key="relocations")


def _data_variable_record(variable: object, address: object | None = None) -> dict[str, object]:
    actual_address = _attr(variable, "address", address)
    symbol = _attr(variable, "symbol")
    return {
        "address": _as_address(actual_address),
        "name": _attr(variable, "name", _attr(symbol, "name")),
        "type": _type_text(_attr(variable, "type")),
        "autoDiscovered": bool(_attr(variable, "auto_discovered", False)),
    }


def _data_variables(args: Mapping[str, object], bv: object) -> dict[str, object]:
    variables = _attr(bv, "data_vars", {}) or {}
    records = []
    if isinstance(variables, Mapping):
        records.extend(
            _data_variable_record(variable, address) for address, variable in variables.items()
        )
    else:
        records.extend(_data_variable_record(variable) for variable in variables)
    return paginate(
        _filter_records(_sort_records(records), args, bv), args, item_key="dataVariables"
    )


def _xref_length(args: Mapping[str, object], bv: object) -> int | None:
    if "length" not in args:
        return None
    return parse_address(bv, args["length"], "length")


def _data_xrefs_to(args: Mapping[str, object], bv: object) -> dict[str, object]:
    target = parse_address(bv, _required(args, "address"), "address")
    length = _xref_length(args, bv)
    getter = _attr(bv, "get_data_refs")
    if not callable(getter):
        raise NativeMcpError("unsupported_api", "BinaryView does not support get_data_refs")
    records = [
        {"source": hex_address(source), "target": hex_address(target)}
        for source in getter(target, length)
    ]
    return paginate(records, args, item_key="references")


def _data_xrefs_from(args: Mapping[str, object], bv: object) -> dict[str, object]:
    source = parse_address(bv, _required(args, "address"), "address")
    length = _xref_length(args, bv)
    getter = _attr(bv, "get_data_refs_from")
    if not callable(getter):
        raise NativeMcpError("unsupported_api", "BinaryView does not support get_data_refs_from")
    records = [
        {"source": hex_address(source), "target": hex_address(target)}
        for target in getter(source, length)
    ]
    return paginate(records, args, item_key="references")


def _escape_bytes(data: bytes) -> str:
    return "".join(chr(byte) if 0x20 <= byte < 0x7F else f"\\x{byte:02x}" for byte in data)


def _string_scan_ranges(args: Mapping[str, object], bv: object) -> list[tuple[int, int]]:
    """Return sorted, disjoint mapped ranges intersected with the requested range."""
    ranges: list[tuple[int, int]] = []
    for segment in _attr(bv, "segments", []) or []:
        try:
            start = int(_attr(segment, "start"))
            end = int(_attr(segment, "end"))
        except (TypeError, ValueError):
            continue
        if end > start:
            ranges.append((start, end))

    if not ranges:
        try:
            start = int(_attr(bv, "start"))
            end = int(_attr(bv, "end"))
        except (TypeError, ValueError) as exc:
            raise NativeMcpError(
                "unsupported_api",
                "BinaryView does not expose a valid address range for string scanning",
            ) from exc
        if end > start:
            ranges.append((start, end))

    ranges.sort()
    merged: list[tuple[int, int]] = []
    for start, end in ranges:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))

    bounds = _address_bounds(args, bv)
    if bounds is None:
        return merged
    bounded = []
    for start, end in merged:
        intersection_start = max(start, bounds[0])
        intersection_end = min(end, bounds[1])
        if intersection_end > intersection_start:
            bounded.append((intersection_start, intersection_end))
    return bounded


def _string_references(args: Mapping[str, object], bv: object) -> Iterable[object]:
    """Yield strings from bounded Binary Ninja range queries, never ``bv.strings``."""
    getter = _attr(bv, "get_strings")
    if not callable(getter):
        raise NativeMcpError("unsupported_api", "BinaryView does not support ranged get_strings")
    for range_start, range_end in _string_scan_ranges(args, bv):
        chunk_start = range_start
        while chunk_start < range_end:
            chunk_end = min(range_end, chunk_start + _STRING_SCAN_CHUNK_BYTES)
            try:
                references = getter(chunk_start, chunk_end - chunk_start)
            except TypeError as exc:
                raise NativeMcpError(
                    "unsupported_api", "BinaryView does not support ranged get_strings"
                ) from exc
            for reference in references:
                try:
                    reference_start = int(_attr(reference, "start"))
                except (TypeError, ValueError):
                    continue
                # Enforce the half-open ranged API contract to prevent a string
                # spanning a chunk boundary from being returned twice.
                if chunk_start <= reference_start < chunk_end:
                    yield reference
            chunk_start = chunk_end


def _string_bytes(reference: object, bv: object, maximum: int) -> bytes:
    if maximum <= 0:
        return b""
    try:
        start = int(_attr(reference, "start"))
        length = max(0, int(_attr(reference, "length", maximum)))
    except (TypeError, ValueError):
        return b""
    reader = _attr(bv, "read")
    if callable(reader):
        try:
            return bytes(reader(start, min(length, maximum)))
        except Exception:
            pass
    return b""


def _decode_string_sample(reference: object, sample: bytes) -> str:
    kind = (_enum_name(_attr(reference, "type")) or "").casefold()
    if "utf32" in kind:
        encodings = ("utf-32", "utf-32-le", "utf-32-be")
    elif "utf16" in kind or "unicode" in kind:
        encodings = ("utf-16", "utf-16-le", "utf-16-be")
    elif "ascii" in kind:
        encodings = ("ascii",)
    else:
        encodings = ("utf-8",)
    candidates = []
    for encoding in encodings:
        try:
            decoded = sample.decode(encoding, errors="ignore").rstrip("\x00")
        except UnicodeError:
            continue
        if decoded:
            candidates.append(decoded)
    return "\n".join(candidates)


def _string_query_text(reference: object, bv: object) -> str:
    """Return a bounded, encoding-tolerant query sample independent of preview size."""
    sample = _string_bytes(reference, bv, _STRING_QUERY_SAMPLE_BYTES)
    return _decode_string_sample(reference, sample)


def _string_record(reference: object, bv: object, preview_bytes: int) -> dict[str, object]:
    preview = _string_bytes(reference, bv, preview_bytes)
    length_value = _attr(reference, "length", len(preview))
    try:
        length = max(0, int(length_value))
    except (TypeError, ValueError):
        length = len(preview)
    preview_value = _decode_string_sample(reference, preview).split("\n", 1)[0]
    return {
        "address": _as_address(_attr(reference, "start")),
        "length": length,
        "type": _enum_name(_attr(reference, "type")),
        "value": preview_value,
        "previewEscaped": _escape_bytes(preview),
        "previewHex": preview.hex(),
        "previewTruncated": length > len(preview),
    }


def _strings(args: Mapping[str, object], bv: object) -> dict[str, object]:
    preview_bytes = parse_integer(args.get("previewBytes", 64), "previewBytes", 0, 256)
    offset = parse_integer(args.get("offset", 0), "offset", 0)
    limit = parse_integer(args.get("limit", 100), "limit", 0, 1000)
    query = _string(args, "query")
    lowered = query.casefold() if query else None
    page: list[dict[str, object]] = []
    total = 0
    for reference in _string_references(args, bv):
        if lowered is not None and lowered not in _string_query_text(reference, bv).casefold():
            continue
        if total >= offset and len(page) < limit:
            page.append(_string_record(reference, bv, preview_bytes))
        total += 1
    more = offset + len(page) < total
    return {
        "strings": json_safe(page),
        "offset": offset,
        "limit": limit,
        "count": len(page),
        "total": total,
        "nextOffset": offset + len(page) if more and page else None,
        "truncated": more,
    }


def _memory_read(args: Mapping[str, object], bv: object) -> dict[str, object]:
    address = parse_address(bv, _required(args, "address"), "address")
    length = parse_address(bv, _required(args, "length"), "length")
    if length > 65536:
        raise NativeMcpError(
            "invalid_params", "Parameter 'length' must be at most 65536 bytes", {"length": length}
        )
    reader = _attr(bv, "read")
    if not callable(reader):
        raise NativeMcpError("unsupported_api", "BinaryView does not support read")
    data = bytes(reader(address, length))
    return {
        "address": hex_address(address),
        "requestedLength": length,
        "bytesRead": len(data),
        "partial": len(data) != length,
        "hex": data.hex(),
        "base64": base64.b64encode(data).decode("ascii"),
        "escaped": _escape_bytes(data),
    }


def _functions(args: Mapping[str, object], bv: object) -> dict[str, object]:
    records = [_function_record(function) for function in _attr(bv, "functions", []) or []]
    return paginate(_filter_records(_sort_records(records), args, bv), args, item_key="functions")


def _function_search(args: Mapping[str, object], bv: object) -> dict[str, object]:
    query = _string(args, "query", required=True)
    forwarded = dict(args)
    forwarded["query"] = query
    return _functions(forwarded, bv)


def _function_info(args: Mapping[str, object], bv: object) -> dict[str, object]:
    return {"function": _function_record(_function(args, bv))}


def _instruction_lines(function: object) -> list[dict[str, object]]:
    result = []
    for tokens, address in _attr(function, "instructions", []) or []:
        if isinstance(tokens, str):
            text = tokens
        else:
            text = "".join(str(token) for token in tokens)
        result.append({"address": hex_address(address), "text": text})
    return result


def _text_result(
    function: object,
    lines: list[dict[str, object]],
    args: Mapping[str, object],
) -> dict[str, object]:
    page = paginate(lines, args, default_limit=1000, item_key="lines")
    page["function"] = _function_record(function)
    page["text"] = "\n".join(str(line["text"]) for line in page["lines"])  # type: ignore[index]
    return page


def _function_disassembly(args: Mapping[str, object], bv: object) -> dict[str, object]:
    function = _function(args, bv)
    lines = _instruction_lines(function)
    if not lines:
        raise NativeMcpError(
            "function_text_unavailable", "Function disassembly text is unavailable"
        )
    return _text_result(function, lines, args)


def _il_lines(il: object, default_address: int) -> list[dict[str, object]]:
    sequence = _attr(il, "instructions")
    if sequence is None:
        root = _attr(il, "root")
        sequence = _attr(root, "lines", []) if root is not None else []
    result = []
    previous = default_address
    for instruction in sequence or []:
        address = _attr(instruction, "address", previous)
        if address is None:
            address = previous
        previous = int(address)
        result.append({"address": hex_address(previous), "text": str(instruction)})
    return result


def _enable_on_demand_analysis(function: object) -> bool:
    """Enable a function skipped by the host's conservative basic load mode."""
    try:
        if not bool(getattr(function, "analysis_skipped")):
            return False
        setattr(function, "analysis_skipped", False)
        reanalyze = getattr(function, "reanalyze", None)
        if callable(reanalyze):
            reanalyze()
        return True
    except Exception:
        return False


def _function_analysis_timeout() -> float:
    raw = os.environ.get(
        "BINJA_MCP_FUNCTION_ANALYSIS_TIMEOUT_SEC",
        os.environ.get(
            "BINJA_MCP_HTTP_READ_TIMEOUT_SEC",
            str(_DEFAULT_FUNCTION_ANALYSIS_TIMEOUT_SEC),
        ),
    )
    try:
        timeout = float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_FUNCTION_ANALYSIS_TIMEOUT_SEC
    if not math.isfinite(timeout) or timeout <= 0:
        return _DEFAULT_FUNCTION_ANALYSIS_TIMEOUT_SEC
    return timeout


def _wait_for_function_form(
    function: object, attribute: str, timeout: float | None = None
) -> object:
    return _wait_for_value(lambda: _attr(function, attribute), timeout)


def _wait_for_value(getter: Callable[[], object], timeout: float | None = None) -> object:
    if timeout is None:
        timeout = _function_analysis_timeout()
    deadline = time.monotonic() + timeout
    while True:
        value = getter()
        if value is not None or time.monotonic() >= deadline:
            return value
        time.sleep(0.05)


def _request_function_form(function: object, attribute: str) -> tuple[object, bool]:
    values, requested = _request_function_forms(function, (attribute,))
    return values[attribute], requested


def _request_function_forms(
    function: object, attributes: tuple[str, ...]
) -> tuple[dict[str, object], bool]:
    values = {attribute: _attr(function, attribute) for attribute in attributes}
    missing = [attribute for attribute, value in values.items() if value is None]
    if not missing:
        return values, False

    requested = False
    reanalyze = _attr(function, "reanalyze")
    if callable(reanalyze):
        try:
            reanalyze()
            requested = True
        except Exception:
            pass

    deadline = time.monotonic() + _function_analysis_timeout()
    while missing:
        # A cold basic-analysis pass can mark the function skipped after the
        # initial readiness check. Re-enable it when that happens; polling IL
        # alone cannot restart a skipped function, even once the view is idle.
        if _enable_on_demand_analysis(function):
            requested = True
        for attribute in missing:
            values[attribute] = _attr(function, attribute)
        missing = [attribute for attribute, value in values.items() if value is None]
        if not missing or time.monotonic() >= deadline:
            break
        time.sleep(0.05)
    return values, requested


def _add_function_analysis_warning(result: dict[str, object], function: object) -> None:
    if not bool(_attr(function, "needs_update", False)):
        return
    warnings = result.setdefault("warnings", [])
    if isinstance(warnings, list):
        warnings.append(
            {
                "code": "function_needs_update",
                "message": (
                    "Function still reports pending analysis updates after IL rendering; "
                    "output may be stale."
                ),
            }
        )


def _rendered_lines(lines: object, default_address: int) -> list[dict[str, object]]:
    result = []
    previous = default_address
    for line in lines or []:
        address = _attr(line, "address", previous)
        if address is None:
            address = previous
        previous = int(address)
        tokens = _attr(line, "tokens")
        text = "".join(str(token) for token in tokens) if tokens is not None else str(line)
        result.append({"address": hex_address(previous), "text": text})
    return result


def _function_decompile(args: Mapping[str, object], bv: object) -> dict[str, object]:
    function = _function(args, bv)
    analysis_enabled = _enable_on_demand_analysis(function)
    forms, forms_requested = _request_function_forms(function, ("hlil", "pseudo_c"))
    hlil = forms["hlil"]
    pseudo_c = forms["pseudo_c"]
    analysis_enabled = analysis_enabled or forms_requested
    renderer = _attr(pseudo_c, "get_linear_lines")
    root = _attr(hlil, "root")
    if not callable(renderer) or root is None:
        raise NativeMcpError(
            "function_text_unavailable",
            "Function Pseudo C text is unavailable; use bn_function_il or bn_function_disassembly",
        )
    lines = _rendered_lines(renderer(root), int(_attr(function, "start", 0)))
    if not lines:
        raise NativeMcpError("function_text_unavailable", "Function Pseudo C text is unavailable")
    result = _text_result(function, lines, args)
    result["language"] = "Pseudo C"
    result["analysisEnabledOnDemand"] = analysis_enabled
    _add_function_analysis_warning(result, function)
    return result


def _function_il(args: Mapping[str, object], bv: object) -> dict[str, object]:
    function = _function(args, bv)
    analysis_enabled = _enable_on_demand_analysis(function)
    level = (_string(args, "level") or "hlil").lower()
    if level not in {"lifted", "llil", "mlil", "hlil"}:
        raise NativeMcpError("invalid_params", "Parameter 'level' has an invalid value")
    form = _string(args, "form") or "text"
    if form != "text":
        raise NativeMcpError("invalid_params", "Only text IL output is supported")
    ssa = _boolean(args, "ssa", False)
    if level == "lifted" and ssa:
        raise NativeMcpError("invalid_params", "Lifted IL does not support SSA form")
    attribute = "lifted_il" if level == "lifted" else level
    il, form_requested = _request_function_form(function, attribute)
    analysis_enabled = analysis_enabled or form_requested
    if ssa and il is not None:
        ssa_form = _attr(il, "ssa_form")
        if ssa_form is None:
            reanalyze = _attr(function, "reanalyze")
            if callable(reanalyze):
                try:
                    reanalyze()
                    analysis_enabled = True
                except Exception:
                    pass
            ssa_form = _wait_for_value(lambda: _attr(il, "ssa_form"))
        il = ssa_form
    if il is None:
        raise NativeMcpError("function_text_unavailable", f"Function {level} text is unavailable")
    lines = _il_lines(il, int(_attr(function, "start", 0)))
    result = _text_result(function, lines, args)
    result.update(
        {
            "level": level,
            "ssa": ssa,
            "form": form,
            "analysisEnabledOnDemand": analysis_enabled,
        }
    )
    _add_function_analysis_warning(result, function)
    return result


def _edge_record(edge: object) -> dict[str, object]:
    target = _attr(edge, "target")
    return {
        "type": _enum_name(_attr(edge, "type")),
        "target": _as_address(_attr(target, "start")),
        "targetIndex": _attr(target, "index"),
        "backEdge": bool(_attr(edge, "back_edge", False)),
        "fallThrough": bool(_attr(edge, "fall_through", False)),
    }


def _function_basic_blocks(args: Mapping[str, object], bv: object) -> dict[str, object]:
    function = _function(args, bv)
    records = []
    for block in _attr(function, "basic_blocks", []) or []:
        records.append(
            {
                "index": _attr(block, "index"),
                "start": _as_address(_attr(block, "start")),
                "end": _as_address(_attr(block, "end")),
                "length": _attr(block, "length"),
                "arch": _attr(_attr(block, "arch"), "name"),
                "outgoingEdges": [
                    _edge_record(edge) for edge in _attr(block, "outgoing_edges", []) or []
                ],
            }
        )
    result = paginate(records, args, item_key="basicBlocks")
    result["function"] = _function_record(function)
    return result


def _function_callers(args: Mapping[str, object], bv: object) -> dict[str, object]:
    function = _function(args, bv)
    references = _attr(function, "caller_sites")
    if references is None:
        getter = _attr(bv, "get_callers")
        references = getter(_attr(function, "start")) if callable(getter) else []
    result = paginate(
        [_reference_record(reference) for reference in references or []],
        args,
        item_key="callers",
    )
    result["function"] = _function_record(function)
    return result


def _function_callees(args: Mapping[str, object], bv: object) -> dict[str, object]:
    function = _function(args, bv)
    getter = _attr(bv, "get_callees")
    records = []
    for reference in _attr(function, "call_sites", []) or []:
        if not callable(getter):
            break
        address = int(_attr(reference, "address", 0))
        for target in getter(address, function, _attr(reference, "arch")):
            target_function = None
            target_getter = _attr(bv, "get_function_at")
            if callable(target_getter):
                target_function = target_getter(target)
            records.append(
                {
                    "callsite": hex_address(address),
                    "target": hex_address(target),
                    "name": _attr(target_function, "name"),
                    "arch": _attr(_attr(reference, "arch"), "name"),
                }
            )
    result = paginate(records, args, item_key="callees")
    result["function"] = _function_record(function)
    return result


def _function_xrefs_to(args: Mapping[str, object], bv: object) -> dict[str, object]:
    function = _function(args, bv)
    getter = _attr(bv, "get_code_refs")
    references = list(getter(_attr(function, "start"))) if callable(getter) else []
    callsites = {
        _attr(reference, "address") for reference in (_attr(function, "caller_sites", []) or [])
    }
    records = [
        _reference_record(reference)
        for reference in references
        if _attr(reference, "address") not in callsites
    ]
    result = paginate(records, args, item_key="references")
    result["function"] = _function_record(function)
    return result


def _function_xrefs_from(args: Mapping[str, object], bv: object) -> dict[str, object]:
    function = _function(args, bv)
    getter = _attr(bv, "get_code_refs_from")
    call_getter = _attr(bv, "get_callees")
    records = []
    seen: set[tuple[int, int]] = set()
    for _tokens, source in _attr(function, "instructions", []) or []:
        calls = (
            set(call_getter(source, function, _attr(function, "arch")))
            if callable(call_getter)
            else set()
        )
        targets = getter(source, function, _attr(function, "arch")) if callable(getter) else []
        for target in targets:
            if target in calls or (source, target) in seen:
                continue
            seen.add((source, target))
            records.append({"source": hex_address(source), "target": hex_address(target)})
    result = paginate(records, args, item_key="references")
    result["function"] = _function_record(function)
    return result


def _function_stack_layout(args: Mapping[str, object], bv: object) -> dict[str, object]:
    function = _function(args, bv)
    parameters = set(_attr(function, "parameter_vars", []) or [])
    records = [
        _variable_record(variable, parameters)
        for variable in _attr(function, "stack_layout", []) or []
    ]
    records.sort(key=lambda item: (int(item["storage"] or 0), str(item["name"] or "")))
    result = paginate(records, args, item_key="stackVariables")
    result["function"] = _function_record(function)
    return result


def _function_complexity(args: Mapping[str, object], bv: object) -> dict[str, object]:
    function = _function(args, bv)
    blocks = list(_attr(function, "basic_blocks", []) or [])
    edges = sum(len(_attr(block, "outgoing_edges", []) or []) for block in blocks)
    calls = len(_attr(function, "call_sites", []) or [])
    variables = len(_attr(function, "vars", []) or [])
    mlil = _attr(function, "mlil")
    mlil_ssa = _attr(mlil, "ssa_form")
    mlil_ssa_edges = sum(
        len(_attr(block, "outgoing_edges", []) or [])
        for block in _attr(mlil_ssa, "basic_blocks", []) or []
    )
    adjacency: dict[int, set[int]] = {}
    for block in blocks:
        index = int(_attr(block, "index", len(adjacency)))
        adjacency.setdefault(index, set())
        for edge in _attr(block, "outgoing_edges", []) or []:
            target = _attr(_attr(edge, "target"), "index")
            if target is not None:
                adjacency[index].add(int(target))
                adjacency.setdefault(int(target), set()).add(index)
    remaining = set(adjacency)
    components = 0
    while remaining:
        components += 1
        pending = [remaining.pop()]
        while pending:
            current = pending.pop()
            neighbors = adjacency[current] & remaining
            remaining.difference_update(neighbors)
            pending.extend(neighbors)
    cyclomatic = edges - len(blocks) + (2 * components) if blocks else 0
    return {
        "function": _function_record(function),
        "metrics": [
            {"metric": "Blocks", "value": len(blocks)},
            {"metric": "Edges", "value": edges},
            {"metric": "Calls", "value": calls},
            {"metric": "Variables", "value": variables},
            {"metric": "MLIL SSA Edge Count", "value": mlil_ssa_edges},
        ],
        "blocks": len(blocks),
        "edges": edges,
        "calls": calls,
        "variables": variables,
        "mlilSsaEdgeCount": mlil_ssa_edges,
        "basicBlockCount": len(blocks),
        "edgeCount": edges,
        "connectedComponents": components,
        "cyclomaticComplexity": max(0, cyclomatic),
        "callsiteCount": calls,
    }


def _comment_get(args: Mapping[str, object], bv: object) -> dict[str, object]:
    address = parse_address(bv, _required(args, "comment"), "comment")
    getter = _attr(bv, "get_comment_at")
    if not callable(getter):
        raise NativeMcpError("unsupported_api", "BinaryView does not support get_comment_at")
    text = getter(address)
    return {"comment": hex_address(address), "text": text if text else None}


def _variables(args: Mapping[str, object], bv: object) -> dict[str, object]:
    function = _function(args, bv)
    parameters = set(_attr(function, "parameter_vars", []) or [])
    records = [
        _variable_record(variable, parameters) for variable in _attr(function, "vars", []) or []
    ]
    records.sort(
        key=lambda item: (str(item["sourceType"]), int(item["index"] or 0), str(item["name"]))
    )
    result = paginate(records, args, item_key="variables")
    result["function"] = _function_record(function)
    return result


def _function_prototype(args: Mapping[str, object], bv: object) -> dict[str, object]:
    function = _function(args, bv)
    parameters = [
        _variable_record(variable) for variable in _attr(function, "parameter_vars", []) or []
    ]
    convention = _attr(function, "calling_convention")
    return {
        "function": _function_record(function),
        "prototype": _type_text(_attr(function, "type")),
        "returnType": _type_text(_attr(function, "return_type")),
        "parameters": parameters,
        "callingConvention": _attr(convention, "name"),
        "hasUserType": bool(_attr(function, "has_explicitly_defined_type", False)),
    }


def _calling_conventions(args: Mapping[str, object], bv: object) -> dict[str, object]:
    function = _function(args, bv)
    platform = _attr(function, "platform")
    owner = platform if platform is not None else _attr(function, "arch")
    conventions = _attr(owner, "calling_conventions", []) or []
    if isinstance(conventions, Mapping):
        conventions = conventions.values()
    default = _attr(owner, "default_calling_convention")
    cdecl = _attr(owner, "cdecl_calling_convention")
    stdcall = _attr(owner, "stdcall_calling_convention")
    fastcall = _attr(owner, "fastcall_calling_convention")
    syscall = _attr(owner, "system_call_convention")
    current = _attr(function, "calling_convention")
    records = []
    for convention in conventions:
        records.append(
            {
                "name": _attr(convention, "name"),
                "isDefault": convention == default,
                "isCdecl": convention == cdecl,
                "isStdcall": convention == stdcall,
                "isFastcall": convention == fastcall,
                "isSyscall": convention == syscall,
                "current": convention == current,
            }
        )
    records.sort(key=lambda item: str(item["name"]))
    return {
        "function": _function_record(function),
        "currentCallingConvention": _attr(current, "name"),
        "callingConventions": records,
    }


def _type_record(name: object, type_object: object, bv: object | None = None) -> dict[str, object]:
    auto_defined = False
    checker = _attr(bv, "is_type_auto_defined") if bv is not None else None
    if callable(checker):
        try:
            auto_defined = bool(checker(name))
        except Exception:
            auto_defined = False
    return {
        "name": str(name),
        "class": _enum_name(_attr(type_object, "type_class")),
        "definition": str(type_object),
        "width": _attr(type_object, "width"),
        "alignment": _attr(type_object, "alignment"),
        "confidence": _attr(type_object, "confidence"),
        "autoDefined": auto_defined,
    }


def _type_records(bv: object) -> list[dict[str, object]]:
    types = _attr(bv, "types", {}) or {}
    if isinstance(types, Mapping):
        pairs = types.items()
    else:
        pairs = ((str(type_object), type_object) for type_object in types)
    return sorted(
        (_type_record(name, type_object, bv) for name, type_object in pairs),
        key=lambda item: str(item["name"]),
    )


def _types(args: Mapping[str, object], bv: object) -> dict[str, object]:
    query = _string(args, "query")
    records = _type_records(bv)
    if query:
        lowered = query.casefold()
        records = [record for record in records if lowered in str(record["name"]).casefold()]
    return paginate(records, args, item_key="types")


def _type_search(args: Mapping[str, object], bv: object) -> dict[str, object]:
    query = _string(args, "query", required=True)
    forwarded = dict(args)
    forwarded["query"] = query
    return _types(forwarded, bv)


def _type_source(bv: object, name: str, type_object: object) -> str:
    getter = _attr(type_object, "get_lines")
    if not callable(getter):
        return f"{type_object}\n"
    try:
        lines = getter(bv, name, 64, False)
    except TypeError:
        lines = getter(bv, name)
    rendered = []
    for line in lines or []:
        tokens = _attr(line, "tokens")
        rendered.append(
            "".join(str(token) for token in tokens) if tokens is not None else str(line)
        )
    return "".join(f"{line}\n" for line in rendered)


def _direct_type_references(bv: object, method_name: str, name: str) -> list[str]:
    getter = _attr(bv, method_name)
    if not callable(getter):
        return []
    return [str(reference) for reference in getter(name)]


def _type_info(args: Mapping[str, object], bv: object) -> dict[str, object]:
    name = _string(args, "type", required=True)
    type_object = resolve_type(bv, name)
    id_getter = _attr(bv, "get_type_id")
    type_id = str(id_getter(name)) if callable(id_getter) else ""
    auto_getter = _attr(bv, "is_type_auto_defined")
    auto_defined = bool(auto_getter(name)) if callable(auto_getter) else False
    result: dict[str, object] = {
        "type": name,
        "id": type_id,
        "class": _enum_name(_attr(type_object, "type_class")),
        "definition": str(type_object),
        "width": _attr(type_object, "width"),
        "alignment": _attr(type_object, "alignment"),
        "autoDefined": auto_defined,
        "source": _type_source(bv, name, type_object),
        "outgoingDirectTypeReferences": _direct_type_references(
            bv, "get_outgoing_direct_type_references", name
        ),
        "incomingDirectTypeReferences": _direct_type_references(
            bv, "get_incoming_direct_type_references", name
        ),
    }
    if (_enum_name(_attr(type_object, "type_class")) or "") == "StructureTypeClass":
        structure_type = _enum_name(_attr(type_object, "type"))
        if structure_type is None:
            structure_type = _enum_name(_attr(_attr(type_object, "structure"), "type"))
        if structure_type is not None:
            result["structureType"] = structure_type
    return result


def _parsed_mapping(value: object) -> list[dict[str, object]]:
    if not isinstance(value, Mapping):
        return []
    return [_type_record(name, type_object) for name, type_object in value.items()]


def _type_parse(args: Mapping[str, object], bv: object) -> dict[str, object]:
    source = _string(args, "source", required=True)
    options = _string_array(args, "options")
    include_dirs = _string_array(args, "includeDirs")
    import_dependencies = _boolean(args, "importDependencies", True)
    parser = _attr(bv, "parse_types_from_string")
    if not callable(parser):
        raise NativeMcpError("unsupported_api", "BinaryView does not support type parsing")
    try:
        parsed = parser(source, options, include_dirs, import_dependencies)
    except (SyntaxError, ValueError) as exc:
        raise NativeMcpError("type_parse_failed", f"Type parse failed: {exc}") from exc
    return {
        "success": True,
        "types": _parsed_mapping(_attr(parsed, "types", {})),
        "variables": _parsed_mapping(_attr(parsed, "variables", {})),
        "functions": _parsed_mapping(_attr(parsed, "functions", {})),
        "errors": str(_attr(parsed, "errors", "") or ""),
    }


def _type_reference_record(reference: object) -> dict[str, object]:
    return {
        "name": str(_attr(reference, "name")),
        "offset": _as_address(_attr(reference, "offset")),
        "referenceType": _enum_name(_attr(reference, "ref_type")),
    }


def _type_xrefs_to(args: Mapping[str, object], bv: object) -> dict[str, object]:
    name = _string(args, "type", required=True)
    resolve_type(bv, name)
    max_items = args.get("maxItems")
    if max_items is not None:
        max_items = parse_integer(max_items, "maxItems", 0, 10000)
    code_getter = _attr(bv, "get_code_refs_for_type")
    data_getter = _attr(bv, "get_data_refs_for_type")
    type_getter = _attr(bv, "get_type_refs_for_type")
    code = list(code_getter(name, max_items)) if callable(code_getter) else []
    remaining = None if max_items is None else max(0, max_items - len(code))
    data = list(data_getter(name, remaining)) if callable(data_getter) else []
    remaining = None if remaining is None else max(0, remaining - len(data))
    type_refs = list(type_getter(name, remaining)) if callable(type_getter) else []
    return {
        "type": name,
        "codeReferences": [_reference_record(reference) for reference in code],
        "dataReferences": [hex_address(address) for address in data],
        "typeReferences": [_type_reference_record(reference) for reference in type_refs],
        "codeReferenceCount": len(code),
        "dataReferenceCount": len(data),
        "typeReferenceCount": len(type_refs),
    }


def _type_xrefs_from(args: Mapping[str, object], bv: object) -> dict[str, object]:
    name = _string(args, "type", required=True)
    resolve_type(bv, name)
    recursive = _boolean(args, "recursive", False)
    method_name = (
        "get_outgoing_recursive_type_references"
        if recursive
        else "get_outgoing_direct_type_references"
    )
    getter = _attr(bv, method_name)
    references = list(getter(name)) if callable(getter) else []
    return {
        "type": name,
        "recursive": recursive,
        "outgoingDirectTypeReferences" if not recursive else "outgoingRecursiveTypeReferences": [
            str(reference) for reference in references
        ],
        "count": len(references),
    }


def _data_at(args: Mapping[str, object], bv: object) -> dict[str, object]:
    address = parse_address(bv, _required(args, "address"), "address")
    functions_getter = _attr(bv, "get_functions_containing")
    sections_getter = _attr(bv, "get_sections_at")
    segment_getter = _attr(bv, "get_segment_at")
    symbol_getter = _attr(bv, "get_symbol_at")
    data_getter = _attr(bv, "get_data_var_at")
    string_getter = _attr(bv, "get_string_at")
    comment_getter = _attr(bv, "get_comment_at")
    functions = list(functions_getter(address)) if callable(functions_getter) else []
    sections = list(sections_getter(address)) if callable(sections_getter) else []
    segment = segment_getter(address) if callable(segment_getter) else None
    symbol = symbol_getter(address) if callable(symbol_getter) else None
    data_variable = data_getter(address) if callable(data_getter) else None
    string = string_getter(address, True) if callable(string_getter) else None
    return {
        "address": hex_address(address),
        "valid": bool(_attr(bv, "is_valid_offset", lambda _address: False)(address)),
        "readable": bool(_attr(bv, "is_offset_readable", lambda _address: False)(address)),
        "writable": bool(_attr(bv, "is_offset_writable", lambda _address: False)(address)),
        "executable": bool(_attr(bv, "is_offset_executable", lambda _address: False)(address)),
        "functions": [_function_record(function) for function in functions],
        "sections": [str(_attr(section, "name", section)) for section in sections],
        "segment": {
            "start": _as_address(_attr(segment, "start")),
            "end": _as_address(_attr(segment, "end")),
        }
        if segment is not None
        else None,
        "symbol": _symbol_record(symbol) if symbol is not None else None,
        "dataVariable": _data_variable_record(data_variable) if data_variable is not None else None,
        "exactDataVariable": bool(
            data_variable is not None and int(_attr(data_variable, "address", -1)) == address
        ),
        "string": {
            "start": _as_address(_attr(string, "start")),
            "length": _attr(string, "length"),
            "type": _enum_name(_attr(string, "type")),
            "value": str(_attr(string, "value", string)),
        }
        if string is not None
        else None,
        "comment": comment_getter(address) if callable(comment_getter) else None,
    }


_HANDLERS: dict[str, Callable[[Mapping[str, object], object], object]] = {
    "bn_analysis_status": _analysis_status,
    "bn_analysis_update": _analysis_update,
    "bn_analysis_update_and_wait": _analysis_update_and_wait,
    "bn_analysis_abort": _analysis_abort,
    "bn_binary_view_triage": _triage,
    "bn_entry_point_list": _entry_points,
    "bn_segment_list": _segments,
    "bn_section_list": _sections,
    "bn_symbol_list": _symbols,
    "bn_symbol_list_at": _symbols_at,
    "bn_import_list": _imports,
    "bn_export_list": _exports,
    "bn_relocation_list": _relocations,
    "bn_data_variable_list": _data_variables,
    "bn_data_xrefs_to": _data_xrefs_to,
    "bn_data_xrefs_from": _data_xrefs_from,
    "bn_string_list": _strings,
    "bn_memory_read": _memory_read,
    "bn_function_list": _functions,
    "bn_function_search": _function_search,
    "bn_function_info": _function_info,
    "bn_function_disassembly": _function_disassembly,
    "bn_function_decompile": _function_decompile,
    "bn_function_il": _function_il,
    "bn_function_basic_blocks": _function_basic_blocks,
    "bn_function_callers": _function_callers,
    "bn_function_callees": _function_callees,
    "bn_function_xrefs_to": _function_xrefs_to,
    "bn_function_xrefs_from": _function_xrefs_from,
    "bn_function_stack_layout": _function_stack_layout,
    "bn_function_complexity": _function_complexity,
    "bn_comment_get": _comment_get,
    "bn_variable_list": _variables,
    "bn_function_prototype_get": _function_prototype,
    "bn_calling_convention_list": _calling_conventions,
    "bn_type_list": _types,
    "bn_type_search": _type_search,
    "bn_type_info": _type_info,
    "bn_type_parse": _type_parse,
    "bn_type_xrefs_to": _type_xrefs_to,
    "bn_type_xrefs_from": _type_xrefs_from,
    "bn_data_at": _data_at,
}

INSPECTION_TOOLS = frozenset(_HANDLERS)


def dispatch_inspection(tool: str, args: dict, bv: object) -> object:
    """Dispatch one native Binary Ninja inspection/analysis tool operation.

    ``NativeMcpError`` is preserved for callers to turn into a structured MCP
    error.  Unexpected Binary Ninja exceptions are normalized so no ctypes or
    SDK object leaks through a JSON boundary.
    """

    if not isinstance(tool, str) or not tool:
        raise NativeMcpError("invalid_params", "Tool name must be a non-empty string")
    if not isinstance(args, dict):
        raise NativeMcpError("invalid_params", "Expected object arguments")
    if bv is None:
        raise NativeMcpError("no_active_binary_view", "No active BinaryView is available")
    handler = _HANDLERS.get(tool)
    if handler is None:
        raise NativeMcpError(
            "unknown_tool",
            f"Unsupported native inspection tool '{tool}'",
            {"available": sorted(_HANDLERS)},
        )
    try:
        return json_safe(handler(args, bv))
    except NativeMcpError:
        raise
    except Exception as exc:
        raise NativeMcpError(
            "binary_ninja_error",
            f"Binary Ninja failed while executing {tool}: {exc}",
            {"tool": tool, "exception": type(exc).__name__},
        ) from exc


__all__ = ["INSPECTION_TOOLS", "NativeMcpError", "dispatch_inspection"]
