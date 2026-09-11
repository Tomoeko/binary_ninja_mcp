from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from contextlib import contextmanager
from enum import IntEnum
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


class SymbolType(IntEnum):
    FunctionSymbol = 0
    ImportAddressSymbol = 1
    ImportedFunctionSymbol = 2
    DataSymbol = 3
    ImportedDataSymbol = 4
    ExternalSymbol = 5
    LibraryFunctionSymbol = 6
    SymbolicFunctionSymbol = 7
    LocalLabelSymbol = 8


class SymbolBinding(IntEnum):
    NoBinding = 0
    LocalBinding = 1
    GlobalBinding = 2
    WeakBinding = 3


class SectionSemantics(IntEnum):
    DefaultSectionSemantics = 0
    ReadOnlyCodeSectionSemantics = 1
    ReadOnlyDataSectionSemantics = 2
    ReadWriteDataSectionSemantics = 3
    ExternalSectionSemantics = 4


class TypeClass(IntEnum):
    IntegerTypeClass = 2
    StructureTypeClass = 4
    EnumerationTypeClass = 5
    FunctionTypeClass = 8


class StructureVariant(IntEnum):
    ClassStructureType = 0
    StructStructureType = 1
    UnionStructureType = 2


class FakeSymbol:
    def __init__(
        self,
        symbol_type,
        address,
        short_name,
        full_name=None,
        raw_name=None,
        binding=None,
        namespace=None,
        ordinal=0,
        *,
        auto=False,
    ):
        self.type = symbol_type
        self.address = address
        self.short_name = short_name
        self.name = short_name
        self.full_name = full_name or short_name
        self.raw_name = raw_name or self.full_name
        self.binding = SymbolBinding.NoBinding if binding is None else binding
        self.namespace = namespace
        self.ordinal = ordinal
        self.auto = auto


class FakeType:
    def __init__(self, text, type_class=TypeClass.IntegerTypeClass, variant=None):
        self.text = text
        self.type_class = type_class
        if variant is not None:
            self.type = variant

    def __str__(self):
        return self.text


class FakeParseResult:
    def __init__(self, *, types=None, variables=None, functions=None):
        self.types = types or {}
        self.variables = variables or {}
        self.functions = functions or {}


class FakeVariable:
    def __init__(self, name, var_type):
        self.name = name
        self.type = var_type
        self.source_type = 1
        self.index = 2
        self.storage = 3

    def set_name_async(self, name):
        self.name = name

    def set_type_async(self, var_type):
        self.type = var_type


class FakeConvention:
    def __init__(self, name):
        self.name = name


class FakeArchitecture:
    name = "test-arch"

    def __init__(self):
        self.calling_conventions = {"archcc": FakeConvention("archcc")}


class FakePlatform:
    def __init__(self):
        self.calling_conventions = [FakeConvention("cdecl")]


class FakeFunction:
    def __init__(self, start=0x1000):
        self.start = start
        self.arch = FakeArchitecture()
        self.platform = FakePlatform()
        self.vars = [FakeVariable("old", FakeType("int"))]
        self.type = FakeType("int old(void)", TypeClass.FunctionTypeClass)
        self.calling_convention = self.platform.calling_conventions[0]

    def set_user_type(self, function_type):
        self.type = function_type


class FakeDataVariable:
    def __init__(self, address, var_type, *, auto=False):
        self.address = address
        self.type = var_type
        self.auto_discovered = auto


class FakeSection:
    def __init__(
        self,
        name,
        start,
        length,
        semantics,
        type_name="",
        align=1,
        entry_size=0,
        linked_section="",
        info_section="",
        info_data=0,
        *,
        auto=False,
    ):
        self.name = name
        self.start = start
        self.length = length
        self.semantics = semantics
        self.type = type_name
        self.align = align
        self.entry_size = entry_size
        self.linked_section = linked_section
        self.info_section = info_section
        self.info_data = info_data
        self.auto_defined = auto


class FakeBinaryView:
    def __init__(self):
        self.comments = {}
        self.symbols = []
        self.function = FakeFunction()
        self.types = {}
        self.auto_types = set()
        self.parsed_sources = {}
        self.data_vars = {}
        self.sections = {}
        self.analysis_updates = 0
        self.analysis_waits = 0
        self.initial_analysis = False
        self.transactions = 0

    def parse_expression(self, expression):
        values = {"entry": 0x1000, "entry + 4": 0x1004, "size": 0x40, "align": 0x10}
        if expression in values:
            return values[expression]
        return int(expression, 0)

    def update_analysis(self):
        self.analysis_updates += 1

    def update_analysis_and_wait(self):
        self.analysis_waits += 1

    def has_initial_analysis(self):
        return self.initial_analysis

    @contextmanager
    def undoable_transaction(self):
        self.transactions += 1
        yield

    def get_comment_at(self, address):
        return self.comments.get(address, "")

    def set_comment_at(self, address, text):
        self.comments[address] = text

    def get_symbols(self, start, length):
        return [symbol for symbol in self.symbols if start <= symbol.address < start + length]

    def define_user_symbol(self, symbol):
        symbol.auto = False
        self.symbols.append(symbol)

    def undefine_user_symbol(self, symbol):
        self.symbols.remove(symbol)

    def get_functions_at(self, address):
        return [self.function] if address == self.function.start else []

    def parse_type_string(self, text, import_dependencies=True):
        if "(" in text:
            return FakeType(text, TypeClass.FunctionTypeClass), "parsed_function"
        return FakeType(text), "parsed_type"

    def parse_types_from_string(
        self, source, options=None, include_dirs=None, import_dependencies=True
    ):
        return self.parsed_sources[source]

    def get_type_by_name(self, name):
        return self.types.get(name)

    def is_type_auto_defined(self, name):
        return name in self.auto_types

    def define_user_type(self, name, type_object):
        self.types[name] = type_object
        self.auto_types.discard(name)

    def undefine_user_type(self, name):
        del self.types[name]

    def rename_type(self, old_name, new_name):
        self.types[new_name] = self.types.pop(old_name)

    def get_data_var_at(self, address):
        return self.data_vars.get(address)

    def define_user_data_var(self, address, type_object):
        result = FakeDataVariable(address, type_object)
        self.data_vars[address] = result
        return result

    def undefine_user_data_var(self, address):
        del self.data_vars[address]

    def get_section_by_name(self, name):
        return self.sections.get(name)

    def add_user_section(
        self,
        name,
        start,
        length,
        semantics,
        type_name,
        align,
        entry_size,
        linked_section,
        info_section,
        info_data,
    ):
        self.sections[name] = FakeSection(
            name,
            start,
            length,
            semantics,
            type_name,
            align,
            entry_size,
            linked_section,
            info_section,
            info_data,
        )

    def remove_user_section(self, name):
        del self.sections[name]


def _load_editing_module():
    package_name = "native_mcp_editing_test_package"
    package = types.ModuleType(package_name)
    package.__path__ = [str(REPO_ROOT / "plugin" / "api")]
    sys.modules[package_name] = package

    fake_bn = types.ModuleType("binaryninja")
    fake_bn.Symbol = FakeSymbol
    fake_bn.SymbolType = SymbolType
    fake_bn.SymbolBinding = SymbolBinding
    fake_bn.SectionSemantics = SectionSemantics
    sys.modules["binaryninja"] = fake_bn

    for module_name in ("native_mcp_common", "native_mcp_editing"):
        qualified = f"{package_name}.{module_name}"
        path = REPO_ROOT / "plugin" / "api" / f"{module_name}.py"
        spec = importlib.util.spec_from_file_location(qualified, path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[qualified] = module
        spec.loader.exec_module(module)
    return sys.modules[f"{package_name}.native_mcp_editing"]


editing = _load_editing_module()
NativeMcpError = sys.modules["native_mcp_editing_test_package.native_mcp_common"].NativeMcpError


class NativeMcpEditingTests(unittest.TestCase):
    def setUp(self):
        self.bv = FakeBinaryView()

    def dispatch(self, tool, **args):
        return editing.dispatch_editing(tool, args, self.bv)

    def assert_error(self, code, tool, **args):
        with self.assertRaises(NativeMcpError) as caught:
            self.dispatch(tool, **args)
        self.assertEqual(caught.exception.code, code)

    def test_comment_mutations_resolve_expressions_and_honor_skip_analysis(self):
        result = self.dispatch("bn_comment_set", comment="entry + 4", text="important")
        self.assertEqual(result["address"], "0x1004")
        self.assertEqual(self.bv.comments[0x1004], "important")
        self.assertEqual((self.bv.transactions, self.bv.analysis_updates), (1, 1))

        deleted = self.dispatch("bn_comment_delete", comment="0x1004", skipAnalysisUpdate=True)
        self.assertTrue(deleted["changed"])
        self.assertEqual(self.bv.comments[0x1004], "")
        self.assertEqual((self.bv.transactions, self.bv.analysis_updates), (2, 1))

    def test_invalid_control_is_rejected_before_mutation(self):
        self.assert_error(
            "invalid_params",
            "bn_comment_set",
            comment="entry",
            text="must not land",
            skipAnalysisUpdate="yes",
        )
        self.assertNotIn(0x1000, self.bv.comments)
        self.assertEqual(self.bv.transactions, 0)

    def test_symbol_define_rename_and_undefine_preserve_metadata(self):
        defined = self.dispatch(
            "bn_symbol_define",
            symbol="entry",
            name="item",
            type="DataSymbol",
            binding="GlobalBinding",
            namespace="ns",
            ordinal=7,
        )
        self.assertEqual(defined["symbol"]["binding"], "GlobalBinding")

        renamed = self.dispatch(
            "bn_symbol_rename",
            symbol="entry",
            name="item",
            newName="renamed",
            type=None,
            namespace=None,
            ordinal=None,
        )
        self.assertEqual(renamed["symbol"]["name"], "renamed")
        self.assertEqual(renamed["symbol"]["namespace"], "ns")

        removed = self.dispatch("bn_symbol_undefine", symbol="entry", name="renamed")
        self.assertTrue(removed["changed"])
        self.assertEqual(self.bv.symbols, [])

    def test_auto_symbol_cannot_be_undefined(self):
        self.bv.symbols.append(FakeSymbol(SymbolType.FunctionSymbol, 0x1000, "auto", auto=True))
        self.assert_error("not_user_defined", "bn_symbol_undefine", symbol="entry", name="auto")

    def test_variable_prototype_and_calling_convention_mutations(self):
        self.bv.initial_analysis = True
        renamed = self.dispatch(
            "bn_variable_rename",
            function="entry",
            variable="old",
            newName="value",
            arch="test-arch",
        )
        self.assertEqual(renamed["newName"], "value")

        typed = self.dispatch(
            "bn_variable_set_type",
            function="entry",
            variable="value",
            arch="",
            definition="unsigned long",
            source=None,
            type=None,
            options=None,
            includeDirs=None,
            importDependencies=True,
            skipAnalysisUpdate=False,
        )
        self.assertEqual(typed["type"], "unsigned long")

        prototype = self.dispatch(
            "bn_function_prototype_set",
            function="entry",
            prototype="int target(int value)",
        )
        self.assertEqual(prototype["prototype"], "int target(int value)")

        convention = self.dispatch(
            "bn_calling_convention_set",
            function="entry",
            callingConvention="archcc",
        )
        self.assertEqual(convention["callingConvention"], "archcc")
        self.assertEqual(self.bv.function.calling_convention.name, "archcc")
        self.assertGreaterEqual(self.bv.analysis_waits, 4)

    def test_completed_analysis_variable_mutation_verifies_postcondition(self):
        self.bv.initial_analysis = True
        variable = self.bv.function.vars[0]
        variable.set_name_async = lambda _name: None
        self.assert_error(
            "variable_rename_failed",
            "bn_variable_rename",
            function="entry",
            variable="old",
            newName="ignored",
        )
        self.assertEqual(self.bv.analysis_waits, 1)

    def test_source_type_selection_rejects_ambiguity(self):
        self.bv.parsed_sources["two declarations"] = FakeParseResult(
            variables={"first": FakeType("int"), "second": FakeType("char")}
        )
        self.assert_error(
            "ambiguous_type",
            "bn_variable_set_type",
            function="entry",
            variable="old",
            source="two declarations",
        )
        selected = self.dispatch(
            "bn_variable_set_type",
            function="entry",
            variable="old",
            source="two declarations",
            type="second",
        )
        self.assertEqual(selected["parsedName"], "second")

    def test_user_type_lifecycle_and_aggregate_kind_checks(self):
        struct_v1 = FakeType(
            "struct Widget { int x; }",
            TypeClass.StructureTypeClass,
            StructureVariant.StructStructureType,
        )
        struct_v2 = FakeType(
            "struct Widget { int x; int y; }",
            TypeClass.StructureTypeClass,
            StructureVariant.StructStructureType,
        )
        union_type = FakeType(
            "union Value { int i; char c; }",
            TypeClass.StructureTypeClass,
            StructureVariant.UnionStructureType,
        )
        enum_type = FakeType("enum Mode { A, B }", TypeClass.EnumerationTypeClass)
        self.bv.parsed_sources.update(
            {
                "struct-v1": FakeParseResult(types={"Widget": struct_v1}),
                "struct-v2": FakeParseResult(types={"Widget": struct_v2}),
                "union": FakeParseResult(types={"Value": union_type}),
                "enum": FakeParseResult(types={"Mode": enum_type}),
            }
        )
        self.dispatch(
            "bn_type_struct_create",
            source="struct-v1",
            type=None,
            options=None,
            includeDirs=None,
            importDependencies=True,
        )
        modified = self.dispatch("bn_type_struct_modify", source="struct-v2")
        self.assertTrue(modified["changed"])
        self.dispatch("bn_type_union_create", source="union")
        self.dispatch("bn_type_enum_create", source="enum")
        self.dispatch("bn_type_rename", type="Value", newType="RenamedValue")
        self.dispatch("bn_type_delete", type="Widget")
        self.assertNotIn("Widget", self.bv.types)
        self.assertIn("RenamedValue", self.bv.types)

    def test_type_define_selection_is_atomic_before_mutation(self):
        self.bv.parsed_sources["aliases"] = FakeParseResult(
            types={"First": FakeType("int"), "Second": FakeType("char")}
        )
        result = self.dispatch("bn_type_define", source="aliases", types=["Second"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(set(self.bv.types), {"Second"})
        self.assert_error("type_not_found", "bn_type_define", source="aliases", types=["Missing"])
        self.assertEqual(set(self.bv.types), {"Second"})

    def test_data_variable_define_and_undefine_enforce_user_ownership(self):
        result = self.dispatch(
            "bn_data_variable_define", datavar="entry + 4", definition="uint32_t"
        )
        self.assertEqual(result["address"], "0x1004")
        self.dispatch("bn_data_variable_undefine", datavar="entry + 4")
        self.assertNotIn(0x1004, self.bv.data_vars)

        self.bv.data_vars[0x1000] = FakeDataVariable(0x1000, FakeType("int"), auto=True)
        self.assert_error("not_user_defined", "bn_data_variable_undefine", datavar="entry")

    def test_section_create_modify_delete_preserves_native_defaults(self):
        created = self.dispatch(
            "bn_section_create",
            section="custom",
            start="entry",
            length="size",
            semantics="ReadOnlyDataSectionSemantics",
        )
        self.assertEqual(created["section"]["entrySize"], 0)
        self.assertEqual(created["section"]["length"], 0x40)

        modified = self.dispatch(
            "bn_section_modify",
            section="custom",
            newSection="renamed",
            start=None,
            length=None,
            semantics=None,
            typeName=None,
            alignment="align",
            entrySize=None,
            linkedSection=None,
            infoSection=None,
            infoData=None,
        )
        self.assertEqual(modified["section"]["section"], "renamed")
        self.assertEqual(modified["section"]["alignment"], 16)
        self.assertNotIn("custom", self.bv.sections)

        self.dispatch("bn_section_delete", section="renamed")
        self.assertEqual(self.bv.sections, {})

    def test_auto_section_cannot_be_modified_or_deleted(self):
        self.bv.sections["auto"] = FakeSection(
            "auto",
            0x1000,
            0x10,
            SectionSemantics.ReadOnlyCodeSectionSemantics,
            auto=True,
        )
        self.assert_error("section_not_user_defined", "bn_section_modify", section="auto", length=4)
        self.assert_error("section_not_user_defined", "bn_section_delete", section="auto")

    def test_section_rejects_zero_length_and_virtual_range_overflow(self):
        self.assert_error(
            "invalid_params",
            "bn_section_create",
            section="zero",
            start="entry",
            length=0,
        )
        self.assert_error(
            "invalid_params",
            "bn_section_create",
            section="overflow",
            start="0xffffffffffffffff",
            length=2,
        )

    def test_dispatch_rejects_unknown_tools_and_parameters(self):
        self.assert_error("tool_not_found", "bn_does_not_exist")
        self.assert_error("invalid_params", "bn_comment_delete", comment="entry", extra=True)

    def test_dispatch_table_covers_the_native_editing_surface(self):
        expected = {
            "bn_comment_set",
            "bn_comment_delete",
            "bn_symbol_define",
            "bn_symbol_rename",
            "bn_symbol_undefine",
            "bn_variable_rename",
            "bn_variable_set_type",
            "bn_function_prototype_set",
            "bn_calling_convention_set",
            "bn_type_define",
            "bn_type_delete",
            "bn_type_rename",
            "bn_type_struct_create",
            "bn_type_struct_modify",
            "bn_type_union_create",
            "bn_type_union_modify",
            "bn_type_enum_create",
            "bn_type_enum_modify",
            "bn_data_variable_define",
            "bn_data_variable_undefine",
            "bn_section_create",
            "bn_section_modify",
            "bn_section_delete",
        }
        self.assertEqual(set(editing._DISPATCH), expected)


if __name__ == "__main__":
    unittest.main()
