from __future__ import annotations

import asyncio
import functools
import importlib.util
import inspect
import unittest

from pydantic import ValidationError

from bridge.native_v6_tools import (
    NATIVE_V6_TOOL_NAMES,
    harden_native_v6_tools,
    register_native_v6_tools,
)

try:
    from mcp.server.fastmcp import FastMCP
except ModuleNotFoundError:
    try:
        from mcp.server.mcpserver import MCPServer as FastMCP
    except ModuleNotFoundError:
        FastMCP = None


EXPECTED_NAMES = {
    "bn_analysis_abort",
    "bn_analysis_status",
    "bn_analysis_update",
    "bn_analysis_update_and_wait",
    "bn_binary_view_get_active",
    "bn_binary_view_info",
    "bn_binary_view_list",
    "bn_binary_view_set_active",
    "bn_binary_view_triage",
    "bn_calling_convention_list",
    "bn_calling_convention_set",
    "bn_comment_delete",
    "bn_comment_get",
    "bn_comment_set",
    "bn_data_at",
    "bn_data_variable_define",
    "bn_data_variable_list",
    "bn_data_variable_undefine",
    "bn_data_xrefs_from",
    "bn_data_xrefs_to",
    "bn_entry_point_list",
    "bn_export_list",
    "bn_function_basic_blocks",
    "bn_function_callees",
    "bn_function_callers",
    "bn_function_complexity",
    "bn_function_decompile",
    "bn_function_disassembly",
    "bn_function_il",
    "bn_function_info",
    "bn_function_list",
    "bn_function_prototype_get",
    "bn_function_prototype_set",
    "bn_function_search",
    "bn_function_stack_layout",
    "bn_function_xrefs_from",
    "bn_function_xrefs_to",
    "bn_import_list",
    "bn_memory_read",
    "bn_open_item_close",
    "bn_open_item_list",
    "bn_open_item_open",
    "bn_open_item_save",
    "bn_project_file_list",
    "bn_project_file_open",
    "bn_relocation_list",
    "bn_section_create",
    "bn_section_delete",
    "bn_section_list",
    "bn_section_modify",
    "bn_segment_list",
    "bn_string_list",
    "bn_symbol_define",
    "bn_symbol_list",
    "bn_symbol_list_at",
    "bn_symbol_rename",
    "bn_symbol_undefine",
    "bn_type_define",
    "bn_type_delete",
    "bn_type_enum_create",
    "bn_type_enum_modify",
    "bn_type_info",
    "bn_type_list",
    "bn_type_parse",
    "bn_type_rename",
    "bn_type_search",
    "bn_type_struct_create",
    "bn_type_struct_modify",
    "bn_type_union_create",
    "bn_type_union_modify",
    "bn_type_xrefs_from",
    "bn_type_xrefs_to",
    "bn_variable_list",
    "bn_variable_rename",
    "bn_variable_set_type",
}


@unittest.skipUnless(importlib.util.find_spec("mcp"), "MCP dependency absent")
class NativeV6ToolTests(unittest.TestCase):
    def setUp(self):
        assert FastMCP is not None
        self.server = FastMCP("native-v6-test")
        raw_tool = self.server.tool

        # Match the bridge's scoping contract closely enough to exercise both
        # branches without importing and populating its global server.
        def scoped_tool(*decorator_args, **decorator_kwargs):
            register = raw_tool(*decorator_args, **decorator_kwargs)

            def decorate(function):
                if function.__name__ == "open_binary":
                    return register(function)
                signature = inspect.signature(function)
                binary = inspect.Parameter(
                    "binary",
                    inspect.Parameter.KEYWORD_ONLY,
                    default="",
                    annotation=str,
                )

                @functools.wraps(function)
                def scoped(*args, binary: str = "", **kwargs):
                    return function(*args, **kwargs)

                scoped.__signature__ = signature.replace(  # type: ignore[attr-defined]
                    parameters=[*signature.parameters.values(), binary]
                )
                return register(scoped)

            return decorate

        self.calls: list[tuple[str, dict[str, object]]] = []
        self.registered = register_native_v6_tools(
            scoped_tool,
            lambda name, arguments: self.calls.append((name, arguments)) or arguments,
        )
        harden_native_v6_tools(self.server)

    def schema(self, name: str) -> dict:
        return self.server._tool_manager.get_tool(name).parameters

    def test_exact_6010601_tool_catalog(self):
        self.assertEqual(len(EXPECTED_NAMES), 75)
        self.assertEqual(NATIVE_V6_TOOL_NAMES, EXPECTED_NAMES)
        self.assertEqual(set(self.server._tool_manager._tools), EXPECTED_NAMES)
        self.assertEqual(set(self.registered), EXPECTED_NAMES)
        for name in EXPECTED_NAMES:
            self.assertEqual(
                self.server._tool_manager.get_tool(name).output_schema["type"],
                "object",
            )

    def test_lifecycle_tools_are_unscoped_but_analysis_tools_are_scoped(self):
        for name in (
            "bn_open_item_list",
            "bn_open_item_open",
            "bn_open_item_save",
            "bn_open_item_close",
            "bn_project_file_list",
            "bn_project_file_open",
            "bn_binary_view_list",
            "bn_binary_view_get_active",
            "bn_binary_view_set_active",
        ):
            self.assertNotIn("binary", self.schema(name).get("properties", {}), name)

        self.assertEqual(self.schema("bn_binary_view_list").get("properties"), {})

        for name in (
            "bn_analysis_status",
            "bn_binary_view_info",
            "bn_function_decompile",
            "bn_memory_read",
            "bn_type_define",
        ):
            self.assertIn("binary", self.schema(name)["properties"], name)
            parameter = inspect.signature(self.registered[name]).parameters["binary"]
            self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)

    def test_representative_native_schemas(self):
        opened = self.schema("bn_open_item_open")
        self.assertIs(opened["additionalProperties"], False)
        self.assertEqual(opened["required"], ["path"])
        self.assertEqual(opened["properties"]["kind"]["enum"], ["auto", "file", "project"])
        self.assertNotIn("default", opened["properties"]["kind"])
        self.assertNotIn("default", opened["properties"]["setActive"])
        self.assertIn("description", opened["properties"]["setActive"])

        memory = self.schema("bn_memory_read")
        self.assertEqual(memory["required"], ["address", "length"])
        self.assertEqual(
            memory["properties"]["length"]["anyOf"],
            [{"type": "integer"}, {"type": "string"}],
        )

        il = self.schema("bn_function_il")
        self.assertEqual(il["required"], ["function"])
        self.assertNotIn("default", il["properties"]["level"])
        self.assertEqual(il["properties"]["limit"]["minimum"], 0)
        self.assertEqual(il["properties"]["limit"]["maximum"], 1000)

        types = self.schema("bn_type_define")
        self.assertEqual(types["required"], ["source"])
        self.assertEqual(types["properties"]["types"]["type"], "array")
        self.assertEqual(types["properties"]["options"]["type"], "array")
        self.assertEqual(types["properties"]["includeDirs"]["type"], "array")
        self.assertNotIn("default", types["properties"]["importDependencies"])

        section = self.schema("bn_section_create")
        self.assertEqual(section["required"], ["section", "start", "length"])
        self.assertNotIn("default", section["properties"]["alignment"])
        self.assertNotIn("default", section["properties"]["semantics"])

    def test_native_argument_models_reject_extras_and_type_coercion(self):
        function_list = self.server._tool_manager.get_tool("bn_function_list")
        model = function_list.fn_metadata.arg_model
        with self.assertRaises(ValidationError):
            model.model_validate({"bogus": 1})
        with self.assertRaises(ValidationError):
            model.model_validate({"limit": "1"})

        opened = self.server._tool_manager.get_tool("bn_open_item_open")
        with self.assertRaises(ValidationError):
            opened.fn_metadata.arg_model.model_validate({"path": "/tmp/sample", "setActve": False})

    def test_hardened_model_preserves_mcp_tool_execution_contract(self):
        tool = self.server._tool_manager.get_tool("bn_binary_view_list")
        result = asyncio.run(tool.run({}, None))
        self.assertEqual(result, {})
        self.assertEqual(self.calls[-1], ("bn_binary_view_list", {}))

    def test_dispatch_forwards_only_native_arguments(self):
        result = self.registered["bn_memory_read"](
            "0x401000",
            16,
            binary="view:7",
        )
        self.assertEqual(result, {"address": "0x401000", "length": 16})
        self.assertEqual(
            self.calls,
            [("bn_memory_read", {"address": "0x401000", "length": 16})],
        )

        self.registered["bn_open_item_open"]("/tmp/sample.bin")
        self.assertEqual(
            self.calls[-1],
            ("bn_open_item_open", {"path": "/tmp/sample.bin"}),
        )

        self.registered["bn_function_list"](
            offset=0,
            limit=100,
            address=None,
            start=None,
            end=None,
            length=None,
            query=None,
            binary="view:7",
        )
        self.assertEqual(
            self.calls[-1],
            ("bn_function_list", {"offset": 0, "limit": 100}),
        )


if __name__ == "__main__":
    unittest.main()
