"""Native Binary Ninja 6 editing-tool compatibility dispatcher.

The official native MCP server is not available in every Binary Ninja build.
This module implements its editing surface directly against a ``BinaryView``
while preserving user-defined/undoable mutation semantics.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import binaryninja as bn

from .native_mcp_common import (
    NativeMcpError,
    hex_address,
    json_safe,
    maybe_analysis_update,
    parse_address,
    parse_integer,
    resolve_function,
    resolve_type,
    undo_transaction,
)

_PARSER_KEYS = {"options", "includeDirs", "importDependencies"}
_CONTROL_KEYS = {"undo", "skipAnalysisUpdate"}


def _require_text(args: Mapping[str, object], key: str, *, allow_empty: bool = False) -> str:
    value = args.get(key)
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise NativeMcpError("invalid_params", f"Parameter '{key}' must be {qualifier}")
    return value if allow_empty else value.strip()


def _optional_text(
    args: Mapping[str, object], key: str, default: str = "", *, allow_empty: bool = True
) -> str:
    if key not in args or args[key] is None:
        return default
    return _require_text(args, key, allow_empty=allow_empty)


def _optional_bool(args: Mapping[str, object], key: str, default: bool) -> bool:
    value = args.get(key, default)
    if not isinstance(value, bool):
        raise NativeMcpError("invalid_params", f"Parameter '{key}' must be a boolean")
    return value


def _optional_value(args: Mapping[str, object], key: str, default: object) -> object:
    value = args.get(key)
    return default if value is None else value


def _string_list(args: Mapping[str, object], key: str) -> list[str]:
    value = args.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise NativeMcpError("invalid_params", f"Parameter '{key}' must be an array of strings")
    return list(value)


def _optional_arch(args: Mapping[str, object]) -> str | None:
    value = args.get("arch")
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not value.strip():
        raise NativeMcpError("invalid_params", "Parameter 'arch' must be a string")
    return value.strip()


def _unsigned_expression(bv: object, value: object, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, str):
        result = parse_address(bv, value, name)
    else:
        result = parse_integer(value, name, minimum=minimum, maximum=0xFFFFFFFFFFFFFFFF)
    if result < minimum:
        raise NativeMcpError(
            "invalid_params", f"Parameter '{name}' must be at least {minimum}", {"value": result}
        )
    return result


def _require_method(target: object, name: str) -> Callable[..., Any]:
    method = getattr(target, name, None)
    if not callable(method):
        raise NativeMcpError("unsupported_api", f"Binary Ninja does not support {name}")
    return method


def _enum_name(value: object) -> str:
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    return str(value).rsplit(".", 1)[-1]


def _enum_member(enum_name: str, member_name: object, parameter: str) -> object:
    if not isinstance(member_name, str) or not member_name:
        raise NativeMcpError(
            "invalid_params", f"Parameter '{parameter}' must be a non-empty string"
        )
    enum_type = getattr(bn, enum_name, None)
    if enum_type is None:
        enum_type = getattr(getattr(bn, "enums", None), enum_name, None)
    try:
        return enum_type[member_name]
    except (KeyError, TypeError, AttributeError) as exc:
        members = list(getattr(enum_type, "__members__", {}))
        raise NativeMcpError(
            "invalid_params",
            f"Unknown {parameter} '{member_name}'",
            {"allowed": members},
        ) from exc


def _validate_controls(args: Mapping[str, object]) -> None:
    _optional_bool(args, "skipAnalysisUpdate", False)
    _optional_bool(args, "undo", True)


def _apply_mutation(
    bv: object,
    args: Mapping[str, object],
    label: str,
    operation: Callable[[], None],
) -> bool:
    _validate_controls(args)
    with undo_transaction(bv, args, label):
        operation()
    has_initial_analysis = getattr(bv, "has_initial_analysis", None)
    wait = False
    if callable(has_initial_analysis):
        try:
            wait = bool(has_initial_analysis())
        except Exception:
            wait = False
    maybe_analysis_update(bv, args, wait=wait)
    return wait and not _optional_bool(args, "skipAnalysisUpdate", False)


def _result(tool: str, **values: object) -> object:
    return json_safe({"tool": tool, **values})


def _comment_set(tool: str, args: Mapping[str, object], bv: object) -> object:
    address = parse_address(bv, args.get("comment"), "comment")
    text = _require_text(args, "text", allow_empty=True)
    getter = _require_method(bv, "get_comment_at")
    setter = _require_method(bv, "set_comment_at")
    previous = getter(address) or ""
    changed = previous != text
    if changed:
        _apply_mutation(bv, args, tool, lambda: setter(address, text))
    return _result(
        tool,
        changed=changed,
        address=hex_address(address),
        previousText=previous,
        text=text,
    )


def _comment_delete(tool: str, args: Mapping[str, object], bv: object) -> object:
    address = parse_address(bv, args.get("comment"), "comment")
    getter = _require_method(bv, "get_comment_at")
    setter = _require_method(bv, "set_comment_at")
    previous = getter(address) or ""
    changed = bool(previous)
    if changed:
        _apply_mutation(bv, args, tool, lambda: setter(address, ""))
    return _result(
        tool,
        changed=changed,
        address=hex_address(address),
        previousText=previous,
    )


def _symbol_namespace(symbol: object) -> str:
    namespace = getattr(symbol, "namespace", None)
    return "" if namespace is None else str(namespace)


def _symbol_record(symbol: object) -> dict[str, object]:
    return {
        "address": hex_address(getattr(symbol, "address")),
        "name": getattr(symbol, "short_name", getattr(symbol, "name", "")),
        "fullName": getattr(symbol, "full_name", getattr(symbol, "name", "")),
        "rawName": getattr(symbol, "raw_name", getattr(symbol, "name", "")),
        "type": _enum_name(getattr(symbol, "type", "")),
        "binding": _enum_name(getattr(symbol, "binding", "")),
        "namespace": _symbol_namespace(symbol),
        "ordinal": int(getattr(symbol, "ordinal", 0)),
        "auto": bool(getattr(symbol, "auto", False)),
    }


def _symbols_at(bv: object, address: int) -> list[object]:
    symbols = list(_require_method(bv, "get_symbols")(address, 1))
    return [symbol for symbol in symbols if int(getattr(symbol, "address", -1)) == address]


def _select_symbol(bv: object, args: Mapping[str, object]) -> object:
    address = parse_address(bv, args.get("symbol"), "symbol")
    symbols = _symbols_at(bv, address)
    if args.get("name") is not None:
        name = _require_text(args, "name")
        symbols = [
            symbol
            for symbol in symbols
            if name
            in {
                str(getattr(symbol, "name", "")),
                str(getattr(symbol, "short_name", "")),
                str(getattr(symbol, "full_name", "")),
                str(getattr(symbol, "raw_name", "")),
            }
        ]
    if args.get("type") is not None:
        symbol_type = _require_text(args, "type")
        symbols = [symbol for symbol in symbols if _enum_name(symbol.type) == symbol_type]
    if args.get("namespace") is not None:
        namespace = _require_text(args, "namespace", allow_empty=True)
        symbols = [symbol for symbol in symbols if _symbol_namespace(symbol) == namespace]
    if args.get("ordinal") is not None:
        ordinal = parse_integer(args["ordinal"], "ordinal", minimum=0)
        symbols = [symbol for symbol in symbols if int(symbol.ordinal) == ordinal]
    if not symbols:
        raise NativeMcpError(
            "symbol_not_found", "No matching symbol was found", {"symbol": hex(address)}
        )
    if len(symbols) != 1:
        raise NativeMcpError(
            "ambiguous_symbol",
            "Multiple matching symbols were found; provide symbol filters",
            {"symbol": hex(address), "matches": [_symbol_record(item) for item in symbols]},
        )
    return symbols[0]


def _make_symbol(
    symbol_type: object,
    address: int,
    name: str,
    *,
    binding: object,
    namespace: object = None,
    ordinal: int = 0,
) -> object:
    symbol_class = getattr(bn, "Symbol", None)
    if symbol_class is None:
        raise NativeMcpError("unsupported_api", "Binary Ninja does not expose Symbol")
    try:
        return symbol_class(
            symbol_type,
            address,
            name,
            binding=binding,
            namespace=namespace,
            ordinal=ordinal,
        )
    except Exception as exc:
        raise NativeMcpError(
            "invalid_params", "Could not construct the requested symbol", {"error": str(exc)}
        ) from exc


def _symbol_define(tool: str, args: Mapping[str, object], bv: object) -> object:
    address = parse_address(bv, args.get("symbol"), "symbol")
    name = _require_text(args, "name")
    type_name = _optional_text(args, "type", "DataSymbol", allow_empty=False)
    binding_name = _optional_text(args, "binding", "NoBinding", allow_empty=False)
    namespace = _optional_text(args, "namespace", "", allow_empty=True)
    ordinal = parse_integer(args.get("ordinal", 0), "ordinal", minimum=0)
    symbol_type = _enum_member("SymbolType", type_name, "type")
    binding = _enum_member("SymbolBinding", binding_name, "binding")

    for existing in _symbols_at(bv, address):
        record = _symbol_record(existing)
        if (
            not record["auto"]
            and record["name"] == name
            and record["type"] == type_name
            and record["binding"] == binding_name
            and record["namespace"] == namespace
            and record["ordinal"] == ordinal
        ):
            return _result(tool, changed=False, symbol=record)

    symbol = _make_symbol(
        symbol_type,
        address,
        name,
        binding=binding,
        namespace=namespace or None,
        ordinal=ordinal,
    )
    define = _require_method(bv, "define_user_symbol")
    _apply_mutation(bv, args, tool, lambda: define(symbol))
    return _result(tool, changed=True, symbol=_symbol_record(symbol))


def _symbol_rename(tool: str, args: Mapping[str, object], bv: object) -> object:
    existing = _select_symbol(bv, args)
    new_name = _require_text(args, "newName")
    old_record = _symbol_record(existing)
    if old_record["name"] == new_name:
        return _result(tool, changed=False, previous=old_record, symbol=old_record)

    renamed = _make_symbol(
        existing.type,
        int(existing.address),
        new_name,
        binding=existing.binding,
        namespace=getattr(existing, "namespace", None),
        ordinal=int(existing.ordinal),
    )
    define = _require_method(bv, "define_user_symbol")
    undefine = _require_method(bv, "undefine_user_symbol")

    def operation() -> None:
        if not bool(getattr(existing, "auto", False)):
            undefine(existing)
        define(renamed)

    _apply_mutation(bv, args, tool, operation)
    return _result(
        tool,
        changed=True,
        previous=old_record,
        symbol=_symbol_record(renamed),
        sourceWasAuto=old_record["auto"],
    )


def _symbol_undefine(tool: str, args: Mapping[str, object], bv: object) -> object:
    symbol = _select_symbol(bv, args)
    if bool(getattr(symbol, "auto", False)):
        raise NativeMcpError(
            "not_user_defined",
            "The selected symbol is auto-defined and cannot be undefined as a user symbol",
            _symbol_record(symbol),
        )
    record = _symbol_record(symbol)
    undefine = _require_method(bv, "undefine_user_symbol")
    _apply_mutation(bv, args, tool, lambda: undefine(symbol))
    return _result(tool, changed=True, symbol=record)


def _resolve_variable(function: object, name: str) -> object:
    variables = list(getattr(function, "vars", []))
    matches = [variable for variable in variables if str(getattr(variable, "name", "")) == name]
    if not matches:
        raise NativeMcpError(
            "variable_not_found",
            "No matching variable was found",
            {"function": hex_address(getattr(function, "start", 0)), "variable": name},
        )
    unique: dict[tuple[object, object, object], object] = {}
    for variable in matches:
        identity = (
            getattr(variable, "source_type", None),
            getattr(variable, "index", None),
            getattr(variable, "storage", None),
        )
        unique.setdefault(identity, variable)
    matches = list(unique.values())
    if len(matches) != 1:
        raise NativeMcpError(
            "ambiguous_variable",
            "Multiple variables have the requested name",
            {"function": hex_address(getattr(function, "start", 0)), "variable": name},
        )
    return matches[0]


def _parser_arguments(args: Mapping[str, object]) -> tuple[list[str], list[str], bool]:
    return (
        _string_list(args, "options"),
        _string_list(args, "includeDirs"),
        _optional_bool(args, "importDependencies", True),
    )


def _parse_source(bv: object, args: Mapping[str, object]) -> object:
    source = _require_text(args, "source")
    options, include_dirs, import_dependencies = _parser_arguments(args)
    parser = _require_method(bv, "parse_types_from_string")
    try:
        return parser(
            source,
            options=options,
            include_dirs=include_dirs,
            import_dependencies=import_dependencies,
        )
    except (SyntaxError, ValueError) as exc:
        raise NativeMcpError(
            "type_parse_failed", "Binary Ninja could not parse the C source", {"error": str(exc)}
        ) from exc


def _source_candidates(
    parsed: object, categories: tuple[str, ...]
) -> list[tuple[str, object, str]]:
    candidates: list[tuple[str, object, str]] = []
    for category in categories:
        values = getattr(parsed, category, {})
        if not isinstance(values, Mapping):
            continue
        for name, type_object in values.items():
            candidates.append((str(name), type_object, category))
    return candidates


def _type_kind(type_object: object) -> str:
    type_class = _enum_name(getattr(type_object, "type_class", ""))
    if type_class == "EnumerationTypeClass":
        return "enum"
    if type_class != "StructureTypeClass":
        return "other"
    variant = _enum_name(getattr(type_object, "type", ""))
    if variant == "StructStructureType":
        return "struct"
    if variant == "UnionStructureType":
        return "union"
    return "other"


def _select_parsed_type(
    bv: object,
    args: Mapping[str, object],
    *,
    categories: tuple[str, ...] = ("types", "variables", "functions"),
    expected_kind: str | None = None,
) -> tuple[str, object, str]:
    parsed = _parse_source(bv, args)
    candidates = _source_candidates(parsed, categories)
    selector = None
    if args.get("type") is not None:
        selector = _require_text(args, "type")
        candidates = [candidate for candidate in candidates if candidate[0] == selector]
    if expected_kind is not None:
        candidates = [
            candidate for candidate in candidates if _type_kind(candidate[1]) == expected_kind
        ]
    if not candidates:
        raise NativeMcpError(
            "type_not_found",
            "No parsed type matched the request",
            {"type": selector, "expectedKind": expected_kind},
        )
    if len(candidates) != 1:
        raise NativeMcpError(
            "ambiguous_type",
            "Multiple parsed types matched the request; provide 'type'",
            {
                "matches": [
                    {"name": name, "category": category, "kind": _type_kind(type_object)}
                    for name, type_object, category in candidates
                ]
            },
        )
    return candidates[0]


def _parse_definition(bv: object, args: Mapping[str, object]) -> object:
    definition = _require_text(args, "definition")
    import_dependencies = _optional_bool(args, "importDependencies", True)
    parser = _require_method(bv, "parse_type_string")
    try:
        result = parser(definition, import_dependencies=import_dependencies)
    except (SyntaxError, ValueError) as exc:
        raise NativeMcpError(
            "type_parse_failed",
            "Binary Ninja could not parse the type definition",
            {"error": str(exc)},
        ) from exc
    return result[0] if isinstance(result, tuple) else result


def _requested_type(bv: object, args: Mapping[str, object]) -> tuple[object, str | None]:
    has_definition = args.get("definition") is not None
    has_source = args.get("source") is not None
    if has_definition == has_source:
        raise NativeMcpError("invalid_params", "Specify exactly one of 'definition' or 'source'")
    if has_definition:
        if args.get("type") is not None:
            raise NativeMcpError("invalid_params", "Parameter 'type' requires 'source'")
        return _parse_definition(bv, args), None
    name, type_object, _category = _select_parsed_type(bv, args)
    return type_object, name


def _variable_rename(tool: str, args: Mapping[str, object], bv: object) -> object:
    arch = _optional_arch(args)
    function = resolve_function(bv, args.get("function"), arch)
    old_name = _require_text(args, "variable")
    new_name = _require_text(args, "newName")
    variable = _resolve_variable(function, old_name)
    if old_name == new_name:
        return _result(
            tool,
            changed=False,
            function=hex_address(getattr(function, "start")),
            variable=old_name,
        )
    setter = _require_method(variable, "set_name_async")
    waited = _apply_mutation(bv, args, tool, lambda: setter(new_name))
    if waited:
        try:
            _resolve_variable(function, new_name)
        except NativeMcpError as exc:
            raise NativeMcpError(
                "variable_rename_failed",
                "Binary Ninja did not apply the requested variable name",
                {"variable": old_name, "newName": new_name},
            ) from exc
    return _result(
        tool,
        changed=True,
        function=hex_address(getattr(function, "start")),
        variable=old_name,
        newName=new_name,
    )


def _variable_set_type(tool: str, args: Mapping[str, object], bv: object) -> object:
    arch = _optional_arch(args)
    function = resolve_function(bv, args.get("function"), arch)
    variable_name = _require_text(args, "variable")
    variable = _resolve_variable(function, variable_name)
    type_object, parsed_name = _requested_type(bv, args)
    previous = getattr(variable, "type", None)
    changed = str(previous) != str(type_object)
    if changed:
        setter = _require_method(variable, "set_type_async")
        waited = _apply_mutation(bv, args, tool, lambda: setter(type_object))
        if waited:
            updated = _resolve_variable(function, variable_name)
            if str(getattr(updated, "type", None)) != str(type_object):
                raise NativeMcpError(
                    "variable_type_update_failed",
                    "Binary Ninja did not apply the requested variable type",
                    {"variable": variable_name, "type": str(type_object)},
                )
    return _result(
        tool,
        changed=changed,
        function=hex_address(getattr(function, "start")),
        variable=variable_name,
        previousType=None if previous is None else str(previous),
        type=str(type_object),
        parsedName=parsed_name,
    )


def _parse_prototype(bv: object, prototype: str) -> object:
    parser = _require_method(bv, "parse_type_string")
    try:
        result = parser(prototype)
    except (SyntaxError, ValueError) as exc:
        raise NativeMcpError(
            "type_parse_failed",
            "Binary Ninja could not parse the function prototype",
            {"error": str(exc)},
        ) from exc
    type_object = result[0] if isinstance(result, tuple) else result
    if _enum_name(getattr(type_object, "type_class", "")) != "FunctionTypeClass":
        raise NativeMcpError("invalid_type", "Parameter 'prototype' must describe a function type")
    return type_object


def _function_prototype_set(tool: str, args: Mapping[str, object], bv: object) -> object:
    arch = _optional_arch(args)
    function = resolve_function(bv, args.get("function"), arch)
    prototype = _require_text(args, "prototype")
    type_object = _parse_prototype(bv, prototype)
    previous = getattr(function, "type", None)
    changed = str(previous) != str(type_object)
    if changed:
        setter = _require_method(function, "set_user_type")
        _apply_mutation(bv, args, tool, lambda: setter(type_object))
    return _result(
        tool,
        changed=changed,
        function=hex_address(getattr(function, "start")),
        previousPrototype=None if previous is None else str(previous),
        prototype=str(type_object),
    )


def _calling_conventions(function: object) -> dict[str, object]:
    result: dict[str, object] = {}
    platform = getattr(function, "platform", None)
    platform_conventions = getattr(platform, "calling_conventions", [])
    if callable(platform_conventions):
        platform_conventions = platform_conventions()
    for convention in platform_conventions or []:
        name = getattr(convention, "name", None)
        if isinstance(name, str):
            result.setdefault(name, convention)
    architecture = getattr(function, "arch", None)
    architecture_conventions = getattr(architecture, "calling_conventions", {})
    if callable(architecture_conventions):
        architecture_conventions = architecture_conventions()
    if isinstance(architecture_conventions, Mapping):
        for name, convention in architecture_conventions.items():
            result.setdefault(str(name), convention)
    return result


def _calling_convention_set(tool: str, args: Mapping[str, object], bv: object) -> object:
    arch = _optional_arch(args)
    function = resolve_function(bv, args.get("function"), arch)
    name = _require_text(args, "callingConvention")
    conventions = _calling_conventions(function)
    convention = conventions.get(name)
    if convention is None:
        raise NativeMcpError(
            "calling_convention_not_found",
            "No matching calling convention was found",
            {"callingConvention": name, "available": sorted(conventions)},
        )
    previous = getattr(getattr(function, "calling_convention", None), "name", None)
    changed = previous != name

    def operation() -> None:
        setattr(function, "calling_convention", convention)

    if changed:
        _apply_mutation(bv, args, tool, operation)
    return _result(
        tool,
        changed=changed,
        function=hex_address(getattr(function, "start")),
        previousCallingConvention=previous,
        callingConvention=name,
    )


def _get_type(bv: object, name: str) -> object | None:
    return _require_method(bv, "get_type_by_name")(name)


def _ensure_user_type(bv: object, name: str) -> object:
    type_object = resolve_type(bv, name)
    checker = getattr(bv, "is_type_auto_defined", None)
    if callable(checker) and checker(name):
        raise NativeMcpError(
            "not_user_defined", "The selected type is not user-defined", {"type": name}
        )
    return type_object


def _type_define(tool: str, args: Mapping[str, object], bv: object) -> object:
    parsed = _parse_source(bv, args)
    candidates = _source_candidates(parsed, ("types",))
    requested = _string_list(args, "types")
    if requested:
        requested_set = set(requested)
        selected = [candidate for candidate in candidates if candidate[0] in requested_set]
        missing = [name for name in requested if name not in {item[0] for item in selected}]
        if missing:
            raise NativeMcpError(
                "type_not_found",
                "Requested types were not present in parsed source",
                {"types": missing},
            )
    else:
        selected = candidates
    if not selected:
        raise NativeMcpError("type_not_found", "The source did not contain any named types")
    duplicates = [name for name, _type_object, _category in selected if _get_type(bv, name)]
    if duplicates:
        raise NativeMcpError(
            "type_already_exists",
            "One or more requested types already exist",
            {"types": duplicates},
        )
    define = _require_method(bv, "define_user_type")

    def operation() -> None:
        for name, type_object, _category in selected:
            define(name, type_object)

    _apply_mutation(bv, args, tool, operation)
    records = [
        {"name": name, "kind": _type_kind(type_object), "definition": str(type_object)}
        for name, type_object, _category in selected
    ]
    return _result(tool, changed=True, count=len(records), types=records)


def _type_delete(tool: str, args: Mapping[str, object], bv: object) -> object:
    name = _require_text(args, "type")
    type_object = _ensure_user_type(bv, name)
    undefine = _require_method(bv, "undefine_user_type")
    _apply_mutation(bv, args, tool, lambda: undefine(name))
    return _result(tool, changed=True, type=name, previousDefinition=str(type_object))


def _type_rename(tool: str, args: Mapping[str, object], bv: object) -> object:
    name = _require_text(args, "type")
    new_name = _require_text(args, "newType")
    _ensure_user_type(bv, name)
    if name == new_name:
        return _result(tool, changed=False, type=name, newType=new_name)
    if _get_type(bv, new_name) is not None:
        raise NativeMcpError(
            "type_already_exists", "The destination type name already exists", {"type": new_name}
        )
    rename = _require_method(bv, "rename_type")
    _apply_mutation(bv, args, tool, lambda: rename(name, new_name))
    return _result(tool, changed=True, type=name, newType=new_name)


def _aggregate_type_edit(
    tool: str,
    args: Mapping[str, object],
    bv: object,
    *,
    kind: str,
    create: bool,
) -> object:
    name, type_object, _category = _select_parsed_type(
        bv, args, categories=("types",), expected_kind=kind
    )
    existing = _get_type(bv, name)
    if create and existing is not None:
        raise NativeMcpError(
            "type_already_exists", "The requested type already exists", {"type": name}
        )
    if not create:
        existing = _ensure_user_type(bv, name)
        existing_kind = _type_kind(existing)
        if existing_kind != kind:
            raise NativeMcpError(
                "invalid_type",
                "The existing type has a different aggregate kind",
                {"type": name, "expectedKind": kind, "actualKind": existing_kind},
            )
    define = _require_method(bv, "define_user_type")
    previous = None if existing is None else str(existing)
    changed = previous != str(type_object)
    if changed:
        _apply_mutation(bv, args, tool, lambda: define(name, type_object))
    return _result(
        tool,
        changed=changed,
        type=name,
        kind=kind,
        previousDefinition=previous,
        definition=str(type_object),
    )


def _data_variable_define(tool: str, args: Mapping[str, object], bv: object) -> object:
    address = parse_address(bv, args.get("datavar"), "datavar")
    type_object, parsed_name = _requested_type(bv, args)
    getter = _require_method(bv, "get_data_var_at")
    existing = getter(address)
    previous = None if existing is None else str(getattr(existing, "type", ""))
    changed = (
        existing is None
        or bool(getattr(existing, "auto_discovered", False))
        or previous != str(type_object)
    )
    if changed:
        define = _require_method(bv, "define_user_data_var")

        def operation() -> None:
            if define(address, type_object) is None:
                raise NativeMcpError(
                    "data_variable_define_failed",
                    "Binary Ninja did not create the requested data variable",
                    {"datavar": hex(address)},
                )

        _apply_mutation(bv, args, tool, operation)
    return _result(
        tool,
        changed=changed,
        address=hex_address(address),
        previousType=previous,
        type=str(type_object),
        parsedName=parsed_name,
    )


def _data_variable_undefine(tool: str, args: Mapping[str, object], bv: object) -> object:
    address = parse_address(bv, args.get("datavar"), "datavar")
    existing = _require_method(bv, "get_data_var_at")(address)
    if existing is None:
        raise NativeMcpError(
            "data_variable_not_found",
            "No data variable exists at the requested address",
            {"datavar": hex(address)},
        )
    if bool(getattr(existing, "auto_discovered", False)):
        raise NativeMcpError(
            "not_user_defined",
            "The selected data variable is not user-defined",
            {"datavar": hex(address)},
        )
    undefine = _require_method(bv, "undefine_user_data_var")
    previous = str(getattr(existing, "type", ""))
    _apply_mutation(bv, args, tool, lambda: undefine(address))
    return _result(tool, changed=True, address=hex_address(address), previousType=previous)


def _section_record(section: object) -> dict[str, object]:
    return {
        "section": str(getattr(section, "name", "")),
        "start": hex_address(getattr(section, "start")),
        "length": int(getattr(section, "length")),
        "semantics": _enum_name(getattr(section, "semantics", "")),
        "typeName": str(getattr(section, "type", "")),
        "alignment": int(getattr(section, "align", 1)),
        "entrySize": int(getattr(section, "entry_size", 0)),
        "linkedSection": str(getattr(section, "linked_section", "")),
        "infoSection": str(getattr(section, "info_section", "")),
        "infoData": int(getattr(section, "info_data", 0)),
        "auto": bool(getattr(section, "auto_defined", False)),
    }


def _section_values(
    bv: object, args: Mapping[str, object], current: object | None = None
) -> dict[str, object]:
    old = _section_record(current) if current is not None else None
    name = (
        _optional_text(args, "newSection", str(old["section"]), allow_empty=False)
        if old is not None
        else _require_text(args, "section")
    )
    if args.get("start") is not None:
        start = parse_address(bv, args["start"], "start")
    elif old is not None:
        start = int(str(old["start"]), 16)
    else:
        raise NativeMcpError("invalid_params", "Missing required parameter 'start'")
    if args.get("length") is not None:
        length = _unsigned_expression(bv, args["length"], "length", minimum=1)
    elif old is not None:
        length = int(old["length"])
    else:
        raise NativeMcpError("invalid_params", "Missing required parameter 'length'")
    if start + length > 0x10000000000000000:
        raise NativeMcpError(
            "invalid_params",
            "Section virtual address range overflows 64 bits",
            {"start": hex(start), "length": length},
        )
    semantics_name = _optional_text(
        args,
        "semantics",
        "DefaultSectionSemantics" if old is None else str(old["semantics"]),
        allow_empty=False,
    )
    semantics = _enum_member("SectionSemantics", semantics_name, "semantics")
    type_name = _optional_text(
        args, "typeName", "" if old is None else str(old["typeName"]), allow_empty=True
    )
    alignment = _unsigned_expression(
        bv,
        _optional_value(args, "alignment", 1 if old is None else old["alignment"]),
        "alignment",
        minimum=1,
    )
    entry_size = _unsigned_expression(
        bv,
        _optional_value(args, "entrySize", 0 if old is None else old["entrySize"]),
        "entrySize",
        minimum=0,
    )
    linked_section = _optional_text(
        args,
        "linkedSection",
        "" if old is None else str(old["linkedSection"]),
        allow_empty=True,
    )
    info_section = _optional_text(
        args,
        "infoSection",
        "" if old is None else str(old["infoSection"]),
        allow_empty=True,
    )
    info_data = _unsigned_expression(
        bv,
        _optional_value(args, "infoData", 0 if old is None else old["infoData"]),
        "infoData",
        minimum=0,
    )
    return {
        "name": name,
        "start": start,
        "length": length,
        "semantics": semantics,
        "type": type_name,
        "align": alignment,
        "entry_size": entry_size,
        "linked_section": linked_section,
        "info_section": info_section,
        "info_data": info_data,
    }


def _add_section(bv: object, values: Mapping[str, object]) -> None:
    _require_method(bv, "add_user_section")(
        values["name"],
        values["start"],
        values["length"],
        values["semantics"],
        values["type"],
        values["align"],
        values["entry_size"],
        values["linked_section"],
        values["info_section"],
        values["info_data"],
    )


def _verify_user_section(bv: object, name: str, code: str) -> object:
    section = _require_method(bv, "get_section_by_name")(name)
    if section is None or bool(getattr(section, "auto_defined", False)):
        raise NativeMcpError(code, "Binary Ninja did not create the requested user section")
    return section


def _section_create(tool: str, args: Mapping[str, object], bv: object) -> object:
    name = _require_text(args, "section")
    getter = _require_method(bv, "get_section_by_name")
    if getter(name) is not None:
        raise NativeMcpError(
            "section_exists", "A section with the requested name already exists", {"section": name}
        )
    values = _section_values(bv, args)

    def operation() -> None:
        _add_section(bv, values)
        _verify_user_section(bv, name, "section_create_failed")

    _apply_mutation(bv, args, tool, operation)
    section = getter(name)
    return _result(tool, changed=True, section=_section_record(section))


def _get_user_section(bv: object, name: str) -> object:
    section = _require_method(bv, "get_section_by_name")(name)
    if section is None:
        raise NativeMcpError(
            "section_not_found", "No matching section was found", {"section": name}
        )
    if bool(getattr(section, "auto_defined", False)):
        raise NativeMcpError(
            "section_not_user_defined",
            "The selected section is not user-defined",
            {"section": name},
        )
    return section


def _values_record(values: Mapping[str, object]) -> dict[str, object]:
    return {
        "section": values["name"],
        "start": hex_address(values["start"]),
        "length": values["length"],
        "semantics": _enum_name(values["semantics"]),
        "typeName": values["type"],
        "alignment": values["align"],
        "entrySize": values["entry_size"],
        "linkedSection": values["linked_section"],
        "infoSection": values["info_section"],
        "infoData": values["info_data"],
        "auto": False,
    }


def _section_modify(tool: str, args: Mapping[str, object], bv: object) -> object:
    name = _require_text(args, "section")
    existing = _get_user_section(bv, name)
    previous = _section_record(existing)
    values = _section_values(bv, args, existing)
    updated = _values_record(values)
    new_name = str(values["name"])
    getter = _require_method(bv, "get_section_by_name")
    if new_name != name and getter(new_name) is not None:
        raise NativeMcpError(
            "section_exists",
            "A section with the requested new name already exists",
            {"section": new_name},
        )
    changed = previous != updated
    if changed:
        remove = _require_method(bv, "remove_user_section")

        def operation() -> None:
            remove(name)
            _add_section(bv, values)
            _verify_user_section(bv, new_name, "section_modify_failed")

        _apply_mutation(bv, args, tool, operation)
    return _result(tool, changed=changed, previous=previous, section=updated)


def _section_delete(tool: str, args: Mapping[str, object], bv: object) -> object:
    name = _require_text(args, "section")
    section = _get_user_section(bv, name)
    previous = _section_record(section)
    remove = _require_method(bv, "remove_user_section")

    def operation() -> None:
        remove(name)
        remaining = _require_method(bv, "get_section_by_name")(name)
        if remaining is not None and not bool(getattr(remaining, "auto_defined", False)):
            raise NativeMcpError(
                "section_delete_failed", "Binary Ninja did not remove the user section"
            )

    _apply_mutation(bv, args, tool, operation)
    return _result(tool, changed=True, section=previous)


_SOURCE_SINGLE_KEYS = {"source", "type", *_PARSER_KEYS}
_SYMBOL_FILTER_KEYS = {"symbol", "name", "type", "namespace", "ordinal"}


_DISPATCH: dict[str, tuple[Callable[[str, Mapping[str, object], object], object], set[str]]] = {
    "bn_comment_set": (_comment_set, {"comment", "text"}),
    "bn_comment_delete": (_comment_delete, {"comment"}),
    "bn_symbol_define": (
        _symbol_define,
        {"symbol", "name", "type", "binding", "namespace", "ordinal"},
    ),
    "bn_symbol_rename": (_symbol_rename, {*_SYMBOL_FILTER_KEYS, "newName"}),
    "bn_symbol_undefine": (_symbol_undefine, _SYMBOL_FILTER_KEYS),
    "bn_variable_rename": (
        _variable_rename,
        {"function", "variable", "newName", "arch"},
    ),
    "bn_variable_set_type": (
        _variable_set_type,
        {"function", "variable", "definition", "source", "type", "arch", *_PARSER_KEYS},
    ),
    "bn_function_prototype_set": (
        _function_prototype_set,
        {"function", "prototype", "arch"},
    ),
    "bn_calling_convention_set": (
        _calling_convention_set,
        {"function", "callingConvention", "arch"},
    ),
    "bn_type_define": (_type_define, {"source", "types", *_PARSER_KEYS}),
    "bn_type_delete": (_type_delete, {"type"}),
    "bn_type_rename": (_type_rename, {"type", "newType"}),
    "bn_type_struct_create": (
        lambda tool, args, bv: _aggregate_type_edit(tool, args, bv, kind="struct", create=True),
        _SOURCE_SINGLE_KEYS,
    ),
    "bn_type_struct_modify": (
        lambda tool, args, bv: _aggregate_type_edit(tool, args, bv, kind="struct", create=False),
        _SOURCE_SINGLE_KEYS,
    ),
    "bn_type_union_create": (
        lambda tool, args, bv: _aggregate_type_edit(tool, args, bv, kind="union", create=True),
        _SOURCE_SINGLE_KEYS,
    ),
    "bn_type_union_modify": (
        lambda tool, args, bv: _aggregate_type_edit(tool, args, bv, kind="union", create=False),
        _SOURCE_SINGLE_KEYS,
    ),
    "bn_type_enum_create": (
        lambda tool, args, bv: _aggregate_type_edit(tool, args, bv, kind="enum", create=True),
        _SOURCE_SINGLE_KEYS,
    ),
    "bn_type_enum_modify": (
        lambda tool, args, bv: _aggregate_type_edit(tool, args, bv, kind="enum", create=False),
        _SOURCE_SINGLE_KEYS,
    ),
    "bn_data_variable_define": (
        _data_variable_define,
        {"datavar", "definition", "source", "type", *_PARSER_KEYS},
    ),
    "bn_data_variable_undefine": (_data_variable_undefine, {"datavar"}),
    "bn_section_create": (
        _section_create,
        {
            "section",
            "start",
            "length",
            "semantics",
            "typeName",
            "alignment",
            "entrySize",
            "linkedSection",
            "infoSection",
            "infoData",
        },
    ),
    "bn_section_modify": (
        _section_modify,
        {
            "section",
            "newSection",
            "start",
            "length",
            "semantics",
            "typeName",
            "alignment",
            "entrySize",
            "linkedSection",
            "infoSection",
            "infoData",
        },
    ),
    "bn_section_delete": (_section_delete, {"section"}),
}

EDITING_TOOLS = frozenset(_DISPATCH)


def dispatch_editing(tool: str, args: dict, bv: object) -> object:
    """Dispatch a native MCP editing tool against ``bv``.

    Results are JSON-safe mutation records. Domain failures use
    :class:`NativeMcpError` so transports can preserve stable error codes.
    """

    if not isinstance(tool, str) or not tool:
        raise NativeMcpError("invalid_params", "Tool name must be a non-empty string")
    if not isinstance(args, dict):
        raise NativeMcpError("invalid_params", "Tool arguments must be an object")
    if bv is None:
        raise NativeMcpError("binary_not_loaded", "No BinaryView is loaded")
    entry = _DISPATCH.get(tool)
    if entry is None:
        raise NativeMcpError("tool_not_found", f"Unknown editing tool '{tool}'")
    handler, allowed = entry
    unknown = sorted(set(args) - allowed - _CONTROL_KEYS)
    if unknown:
        raise NativeMcpError("invalid_params", "Unknown tool parameters", {"parameters": unknown})
    return handler(tool, args, bv)


__all__ = ["EDITING_TOOLS", "dispatch_editing"]
