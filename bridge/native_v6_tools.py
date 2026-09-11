"""Binary Ninja 6.0 native-MCP compatible tool registrations.

Binary Ninja 6.0.10601 introduced a native MCP server with a stable ``bn_*``
vocabulary.  The Personal edition does not ship the standalone
``binaryninja_mcp`` executable, so the headless bridge exposes the same names
through its existing host.  This module deliberately contains only schema and
dispatch glue: the caller owns the transport and implements ``call(name,
arguments)``.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any, Literal

NativeCall = Callable[[str, dict[str, Any]], Any]
ToolDecorator = Callable[..., Callable[[Callable[..., Any]], Callable[..., Any]]]

_MISSING = object()


@dataclass(frozen=True)
class _Parameter:
    name: str
    annotation: Any
    default: Any = _MISSING


@dataclass(frozen=True)
class _Tool:
    name: str
    description: str
    parameters: tuple[_Parameter, ...] = ()
    target_free: bool = False


_UnsignedExpression = int | str
_OpenKind = Literal["auto", "file", "project"]
_CloseMode = Literal["prompt", "save", "discard"]
_IlLevel = Literal["lifted", "llil", "mlil", "hlil"]
_IlForm = Literal["text"]
_SectionSemantics = Literal[
    "DefaultSectionSemantics",
    "ReadOnlyCodeSectionSemantics",
    "ReadOnlyDataSectionSemantics",
    "ReadWriteDataSectionSemantics",
    "ExternalSectionSemantics",
]
_SymbolType = Literal[
    "FunctionSymbol",
    "ImportAddressSymbol",
    "ImportedFunctionSymbol",
    "DataSymbol",
    "ImportedDataSymbol",
    "ExternalSymbol",
    "LibraryFunctionSymbol",
    "SymbolicFunctionSymbol",
    "LocalLabelSymbol",
]
_SymbolBinding = Literal["NoBinding", "LocalBinding", "GlobalBinding", "WeakBinding"]


def _required(name: str, annotation: Any) -> _Parameter:
    return _Parameter(name, annotation)


def _optional(name: str, annotation: Any, default: Any) -> _Parameter:
    return _Parameter(name, annotation, default)


_OFFSET = _optional("offset", int, 0)
_LIMIT = _optional("limit", int, 100)
_TEXT_LIMIT = _optional("limit", int, 1000)
_ARCH = _optional("arch", str, "")
_FUNCTION = _required("function", str)
_PAGINATION = (_OFFSET, _LIMIT)
_FUNCTION_SELECTOR = (_FUNCTION, _ARCH)
_FUNCTION_PAGE = (_FUNCTION, _ARCH, _OFFSET, _LIMIT)
_FUNCTION_TEXT = (_FUNCTION, _ARCH, _OFFSET, _TEXT_LIMIT)
_RANGE_LIST = (
    _OFFSET,
    _LIMIT,
    _optional("address", str, None),
    _optional("start", str, None),
    _optional("end", str, None),
    _optional("length", _UnsignedExpression, None),
    _optional("query", str, None),
)
_TYPE_PARSE_OPTIONS = (
    _optional("options", list[str], None),
    _optional("includeDirs", list[str], None),
    _optional("importDependencies", bool, True),
)
_TYPE_SOURCE = (
    _required("source", str),
    _optional("type", str, None),
    *_TYPE_PARSE_OPTIONS,
)
# Names, parameter spelling, enum values, and documented defaults mirror the
# tool schemas embedded in Binary Ninja 6.0.10601.  Optional values whose native
# schema is represented by omission use a None default while retaining the
# native non-null value annotation; the dispatcher forwards only arguments the
# MCP client actually supplied.
_TOOLS: tuple[_Tool, ...] = (
    _Tool("bn_analysis_abort", "Abort active analysis work for the active binary view."),
    _Tool("bn_analysis_status", "Return analysis state and progress for the active binary view."),
    _Tool(
        "bn_analysis_update", "Start an asynchronous analysis update for the active binary view."
    ),
    _Tool(
        "bn_analysis_update_and_wait",
        "Run analysis update for the active binary view and wait for completion.",
    ),
    _Tool(
        "bn_binary_view_get_active",
        "Return the active analyzed BinaryView, if any.",
        target_free=True,
    ),
    _Tool("bn_binary_view_info", "Return metadata for the active analyzed BinaryView."),
    _Tool(
        "bn_binary_view_list",
        "List created and valid uncreated BinaryViews for open items.",
        target_free=True,
    ),
    _Tool(
        "bn_binary_view_set_active",
        "Activate a BinaryView by handle, creating it when necessary.",
        (_required("binaryView", str),),
        target_free=True,
    ),
    _Tool("bn_binary_view_triage", "Return a compact read-only summary of the active BinaryView."),
    _Tool(
        "bn_calling_convention_list",
        "List calling conventions available to a function.",
        _FUNCTION_SELECTOR,
    ),
    _Tool(
        "bn_calling_convention_set",
        "Set a function user calling convention.",
        (
            _FUNCTION,
            _required("callingConvention", str),
            _ARCH,
        ),
    ),
    _Tool("bn_comment_get", "Return an address comment.", (_required("comment", str),)),
    _Tool(
        "bn_comment_set",
        "Set an address comment.",
        (_required("comment", str), _required("text", str)),
    ),
    _Tool("bn_comment_delete", "Delete an address comment.", (_required("comment", str),)),
    _Tool("bn_data_at", "Return analysis metadata at an address.", (_required("address", str),)),
    _Tool(
        "bn_data_variable_define",
        "Define a user data variable at an address.",
        (
            _required("datavar", str),
            _optional("definition", str, None),
            _optional("source", str, None),
            _optional("type", str, None),
            *_TYPE_PARSE_OPTIONS,
        ),
    ),
    _Tool("bn_data_variable_list", "List data variables in the active BinaryView.", _RANGE_LIST),
    _Tool(
        "bn_data_variable_undefine",
        "Undefine a user data variable at an address.",
        (_required("datavar", str),),
    ),
    _Tool(
        "bn_data_xrefs_from",
        "List data references out of an address or range.",
        (
            _required("address", str),
            _optional("length", _UnsignedExpression, None),
            _OFFSET,
            _LIMIT,
        ),
    ),
    _Tool(
        "bn_data_xrefs_to",
        "List data references into an address or range.",
        (
            _required("address", str),
            _optional("length", _UnsignedExpression, None),
            _OFFSET,
            _LIMIT,
        ),
    ),
    _Tool("bn_entry_point_list", "List entry point functions.", _PAGINATION),
    _Tool("bn_export_list", "List export symbols.", _RANGE_LIST),
    _Tool(
        "bn_function_basic_blocks",
        "List function basic blocks and control-flow edges.",
        _FUNCTION_PAGE,
    ),
    _Tool("bn_function_callees", "List callees reached from function callsites.", _FUNCTION_PAGE),
    _Tool("bn_function_callers", "List callsites that call a function.", _FUNCTION_PAGE),
    _Tool(
        "bn_function_complexity", "Return derived function complexity metrics.", _FUNCTION_SELECTOR
    ),
    _Tool("bn_function_decompile", "Render function Pseudo C text.", _FUNCTION_TEXT),
    _Tool("bn_function_disassembly", "Render function disassembly text.", _FUNCTION_TEXT),
    _Tool(
        "bn_function_il",
        "Render function intermediate-language text.",
        (
            _FUNCTION,
            _ARCH,
            _optional("level", _IlLevel, "hlil"),
            _optional("ssa", bool, False),
            _optional("form", _IlForm, "text"),
            _OFFSET,
            _TEXT_LIMIT,
        ),
    ),
    _Tool("bn_function_info", "Return a lightweight function summary.", _FUNCTION_SELECTOR),
    _Tool("bn_function_list", "List functions in the active BinaryView.", _RANGE_LIST),
    _Tool("bn_function_prototype_get", "Return a function prototype.", _FUNCTION_SELECTOR),
    _Tool(
        "bn_function_prototype_set",
        "Set a function user prototype.",
        (_FUNCTION, _required("prototype", str), _ARCH),
    ),
    _Tool(
        "bn_function_search",
        "Search function names by case-insensitive substring.",
        (_required("query", str), _OFFSET, _LIMIT),
    ),
    _Tool("bn_function_stack_layout", "List function stack variables.", _FUNCTION_PAGE),
    _Tool(
        "bn_function_xrefs_from", "List non-call code references out of a function.", _FUNCTION_PAGE
    ),
    _Tool("bn_function_xrefs_to", "List non-call code references into a function.", _FUNCTION_PAGE),
    _Tool("bn_import_list", "List import symbols.", _RANGE_LIST),
    _Tool(
        "bn_memory_read",
        "Read bytes from the active BinaryView without modifying it.",
        (_required("address", str), _required("length", _UnsignedExpression)),
    ),
    _Tool(
        "bn_open_item_close",
        "Close an open item by handle.",
        (_required("openItem", str), _optional("save", _CloseMode, "prompt")),
        target_free=True,
    ),
    _Tool(
        "bn_open_item_list",
        "List files, databases, and projects known to Binary Ninja.",
        _PAGINATION,
        True,
    ),
    _Tool(
        "bn_open_item_open",
        "Open a file, database, or project path.",
        (
            _required("path", str),
            _optional("kind", _OpenKind, "auto"),
            _optional("setActive", bool, True),
        ),
        target_free=True,
    ),
    _Tool(
        "bn_open_item_save",
        "Save an open file or database item by handle.",
        (_required("openItem", str),),
        target_free=True,
    ),
    _Tool(
        "bn_project_file_list",
        "List files contained in an open Binary Ninja project.",
        (_required("project", str), _OFFSET, _LIMIT),
        target_free=True,
    ),
    _Tool(
        "bn_project_file_open",
        "Open a file from an open Binary Ninja project.",
        (
            _required("project", str),
            _optional("projectFile", str, None),
            _optional("pathInProject", str, None),
            _optional("setActive", bool, True),
        ),
        target_free=True,
    ),
    _Tool("bn_relocation_list", "List relocations.", _RANGE_LIST),
    _Tool(
        "bn_section_create",
        "Create a persistent user-defined section in mapped memory.",
        (
            _required("section", str),
            _required("start", str),
            _required("length", _UnsignedExpression),
            _optional("semantics", _SectionSemantics, "DefaultSectionSemantics"),
            _optional("typeName", str, ""),
            _optional("alignment", _UnsignedExpression, 1),
            _optional("entrySize", _UnsignedExpression, 0),
            _optional("linkedSection", str, ""),
            _optional("infoSection", str, ""),
            _optional("infoData", _UnsignedExpression, 0),
            _optional("skipAnalysisUpdate", bool, False),
        ),
    ),
    _Tool(
        "bn_section_delete",
        "Delete a user-defined section.",
        (_required("section", str), _optional("skipAnalysisUpdate", bool, False)),
    ),
    _Tool("bn_section_list", "List sections.", _PAGINATION),
    _Tool(
        "bn_section_modify",
        "Modify a user-defined section.",
        (
            _required("section", str),
            _optional("newSection", str, None),
            _optional("start", str, None),
            _optional("length", _UnsignedExpression, None),
            _optional("semantics", _SectionSemantics, None),
            _optional("typeName", str, None),
            _optional("alignment", _UnsignedExpression, None),
            _optional("entrySize", _UnsignedExpression, None),
            _optional("linkedSection", str, None),
            _optional("infoSection", str, None),
            _optional("infoData", _UnsignedExpression, None),
            _optional("skipAnalysisUpdate", bool, False),
        ),
    ),
    _Tool("bn_segment_list", "List memory segments.", _PAGINATION),
    _Tool(
        "bn_string_list",
        "List strings in the active BinaryView.",
        (*_RANGE_LIST, _optional("previewBytes", int, 64)),
    ),
    _Tool(
        "bn_symbol_define",
        "Define a user symbol at an address.",
        (
            _required("symbol", str),
            _required("name", str),
            _optional("type", _SymbolType, "DataSymbol"),
            _optional("binding", _SymbolBinding, "NoBinding"),
            _optional("namespace", str, ""),
            _optional("ordinal", int, 0),
        ),
    ),
    _Tool("bn_symbol_list", "List symbols.", _RANGE_LIST),
    _Tool("bn_symbol_list_at", "List symbols exactly at an address.", (_required("address", str),)),
    _Tool(
        "bn_symbol_rename",
        "Define a renamed user symbol for a selected symbol.",
        (
            _required("symbol", str),
            _required("newName", str),
            _optional("name", str, None),
            _optional("type", _SymbolType, None),
            _optional("namespace", str, None),
            _optional("ordinal", int, None),
        ),
    ),
    _Tool(
        "bn_symbol_undefine",
        "Undefine a selected user symbol.",
        (
            _required("symbol", str),
            _optional("name", str, None),
            _optional("type", _SymbolType, None),
            _optional("namespace", str, None),
            _optional("ordinal", int, None),
        ),
    ),
    _Tool(
        "bn_type_define",
        "Parse C source and define selected user types.",
        (
            _required("source", str),
            _optional("types", list[str], None),
            *_TYPE_PARSE_OPTIONS,
        ),
    ),
    _Tool("bn_type_delete", "Delete a user type.", (_required("type", str),)),
    _Tool("bn_type_enum_create", "Create an enum type from C source.", _TYPE_SOURCE),
    _Tool("bn_type_enum_modify", "Modify an enum type from C source.", _TYPE_SOURCE),
    _Tool("bn_type_info", "Return type information.", (_required("type", str),)),
    _Tool(
        "bn_type_list",
        "List types.",
        (_OFFSET, _LIMIT, _optional("query", str, None)),
    ),
    _Tool(
        "bn_type_parse",
        "Parse C source into types.",
        (_required("source", str), *_TYPE_PARSE_OPTIONS),
    ),
    _Tool(
        "bn_type_rename",
        "Rename a type.",
        (_required("type", str), _required("newType", str)),
    ),
    _Tool(
        "bn_type_search",
        "Search types by case-insensitive substring.",
        (_required("query", str), _OFFSET, _LIMIT),
    ),
    _Tool("bn_type_struct_create", "Create a struct type from C source.", _TYPE_SOURCE),
    _Tool("bn_type_struct_modify", "Modify a struct type from C source.", _TYPE_SOURCE),
    _Tool("bn_type_union_create", "Create a union type from C source.", _TYPE_SOURCE),
    _Tool("bn_type_union_modify", "Modify a union type from C source.", _TYPE_SOURCE),
    _Tool(
        "bn_type_xrefs_from",
        "List outgoing type references from a named type.",
        (_required("type", str), _optional("recursive", bool, False)),
    ),
    _Tool(
        "bn_type_xrefs_to",
        "List code, data, and type references to a named type.",
        (_required("type", str), _optional("maxItems", int, None)),
    ),
    _Tool("bn_variable_list", "List variables for a function.", _FUNCTION_PAGE),
    _Tool(
        "bn_variable_rename",
        "Rename a function variable.",
        (
            _FUNCTION,
            _required("variable", str),
            _required("newName", str),
            _ARCH,
            _optional("skipAnalysisUpdate", bool, False),
        ),
    ),
    _Tool(
        "bn_variable_set_type",
        "Set a function variable type.",
        (
            _FUNCTION,
            _required("variable", str),
            _ARCH,
            _optional("definition", str, None),
            _optional("source", str, None),
            _optional("type", str, None),
            *_TYPE_PARSE_OPTIONS,
            _optional("skipAnalysisUpdate", bool, False),
        ),
    ),
)

NATIVE_V6_TOOL_NAMES = frozenset(tool.name for tool in _TOOLS)

if len(_TOOLS) != 75 or len(NATIVE_V6_TOOL_NAMES) != 75:
    raise RuntimeError("Binary Ninja 6.0 compatibility catalog must contain exactly 75 tools")


def _signature(parameters: tuple[_Parameter, ...]) -> inspect.Signature:
    return inspect.Signature(
        [
            inspect.Parameter(
                parameter.name,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=parameter.annotation,
                **({} if parameter.default is _MISSING else {"default": parameter.default}),
            )
            for parameter in parameters
        ],
        return_annotation=dict[str, Any],
    )


def _make_dispatcher(tool: _Tool, call: NativeCall) -> Callable[..., Any]:
    signature = _signature(tool.parameters)

    def dispatch(*args: Any, **kwargs: Any) -> Any:
        # ``__signature__`` gives FastMCP the native schema while binding here
        # keeps direct Python calls and MCP calls on the same validation path.
        bound = signature.bind(*args, **kwargs)
        # FastMCP materializes optional defaults before invoking a tool. The
        # native schemas represent these None-valued fields by omission, and
        # forwarding them would make mutually-exclusive filters look present.
        arguments = {name: value for name, value in bound.arguments.items() if value is not None}
        return call(tool.name, arguments)

    # ``scoped_tool`` decides whether to append its keyword-only ``binary``
    # selector from the Python function name.  Reuse its established lifecycle
    # sentinel while the decorator's explicit name remains the exact native
    # ``bn_*`` name.
    dispatch.__name__ = "open_binary" if tool.target_free else tool.name
    dispatch.__qualname__ = tool.name
    dispatch.__doc__ = tool.description
    dispatch.__signature__ = signature  # type: ignore[attr-defined]
    return dispatch


def register_native_v6_tools(
    scoped_tool: ToolDecorator,
    call: NativeCall,
) -> dict[str, Callable[..., Any]]:
    """Register Binary Ninja 6.0.10601's exact 75-tool native MCP surface.

    ``scoped_tool`` is the bridge decorator, which appends a keyword-only
    ``binary`` selector and scopes transport calls for active-BinaryView tools.
    Handle-based file/project/BinaryView lifecycle tools are registered without
    that selector.  ``call`` receives the native tool name and only the native
    arguments supplied by the client.
    """

    registered: dict[str, Callable[..., Any]] = {}
    for tool in _TOOLS:
        dispatcher = _make_dispatcher(tool, call)
        try:
            decorator = scoped_tool(
                name=tool.name,
                description=tool.description,
                structured_output=True,
            )
        except TypeError:
            # Older MCP SDKs predate the explicit structured-output switch;
            # the dict return annotation still gives them the best available
            # schema without dropping the native tool surface entirely.
            decorator = scoped_tool(name=tool.name, description=tool.description)
        registered[tool.name] = decorator(dispatcher)
    return registered


_PARAMETER_DESCRIPTIONS = {
    "offset": "Zero-based item offset for pagination. Defaults to 0.",
    "limit": "Maximum items to return. Defaults to 100 and is capped at 1000.",
    "address": (
        "Active binary view address expression. Accepts hex, symbols, and Binary Ninja expressions."
    ),
    "start": "Start address expression for a range in the active binary view.",
    "end": "Exclusive end address expression; cannot be combined with length.",
    "length": "Length in bytes as an integer or Binary Ninja expression string.",
    "query": "Case-insensitive substring filter, not a regular expression.",
    "binary": (
        "Headless target selector. Pass a returned native BinaryView handle verbatim or "
        "use a stable view:N selector or absolute path for the current analyzed view."
    ),
}


def _parameter_description(name: str) -> str:
    known = _PARAMETER_DESCRIPTIONS.get(name)
    if known is not None:
        return known
    words = re.sub(r"(?<!^)(?=[A-Z])", " ", name).replace("_", " ").lower()
    return f"Value for {words}."


def _strict_field(parameter: _Parameter):
    from pydantic import Field

    constraints: dict[str, object] = {"description": _parameter_description(parameter.name)}
    if parameter.name in {"offset", "limit", "previewBytes", "maxItems"}:
        constraints["ge"] = 0
    if parameter.name == "limit":
        constraints["le"] = 1000
    elif parameter.name == "previewBytes":
        constraints["le"] = 256
    elif parameter.name == "maxItems":
        constraints["le"] = 10000
    return Annotated[parameter.annotation, Field(**constraints)]


def _schema_without_pydantic_metadata(value: object) -> object:
    if isinstance(value, list):
        return [_schema_without_pydantic_metadata(item) for item in value]
    if not isinstance(value, dict):
        return value
    return {
        key: _schema_without_pydantic_metadata(item)
        for key, item in value.items()
        if key not in {"default", "title"}
    }


def harden_native_v6_tools(server: object) -> None:
    """Install strict, closed argument models on the registered native tools.

    MCP's default generated Pydantic models coerce primitive types and ignore
    unknown keys. Native Binary Ninja 6 schemas are closed objects, and silently
    ignoring a typo such as ``setActve`` can turn a lifecycle call into an
    unintended mutation. Keep defaults for invocation while advertising and
    enforcing strict native-style inputs.
    """
    from pydantic import ConfigDict, create_model

    manager = getattr(server, "_tool_manager", None)
    getter = getattr(manager, "get_tool", None)
    if not callable(getter):
        raise RuntimeError("The installed MCP SDK does not expose registered tool models")

    first_registered = getter(_TOOLS[0].name)
    if first_registered is None:
        raise RuntimeError(f"Native MCP tool was not registered: {_TOOLS[0].name}")
    original_model = first_registered.fn_metadata.arg_model
    argument_base = next(
        (
            candidate
            for candidate in original_model.__mro__[1:]
            if hasattr(candidate, "model_dump_one_level")
        ),
        None,
    )
    if argument_base is None:
        raise RuntimeError("The installed MCP SDK argument model contract is unsupported")

    class _StrictNativeArguments(argument_base):
        model_config = ConfigDict(
            **dict(getattr(argument_base, "model_config", {})),
            extra="forbid",
            strict=True,
        )

    for tool_spec in _TOOLS:
        registered = getter(tool_spec.name)
        if registered is None:
            raise RuntimeError(f"Native MCP tool was not registered: {tool_spec.name}")
        parameters = list(tool_spec.parameters)
        if not tool_spec.target_free:
            parameters.append(_Parameter("binary", str, ""))
        fields = {
            parameter.name: (
                _strict_field(parameter),
                ... if parameter.default is _MISSING else parameter.default,
            )
            for parameter in parameters
        }
        model = create_model(
            f"{tool_spec.name}Arguments",
            __base__=_StrictNativeArguments,
            **fields,
        )
        registered.fn_metadata.arg_model = model
        schema = _schema_without_pydantic_metadata(model.model_json_schema(by_alias=True))
        if not isinstance(schema, dict):
            raise RuntimeError(f"Invalid generated schema for {tool_spec.name}")
        registered.parameters = schema


__all__ = [
    "NATIVE_V6_TOOL_NAMES",
    "harden_native_v6_tools",
    "register_native_v6_tools",
]
