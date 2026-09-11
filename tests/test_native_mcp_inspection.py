from __future__ import annotations

import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PACKAGE = "_native_mcp_inspection_fixture"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_native_modules():
    package = types.ModuleType(FIXTURE_PACKAGE)
    package.__path__ = []
    api_package = types.ModuleType(f"{FIXTURE_PACKAGE}.api")
    api_package.__path__ = []
    sys.modules[FIXTURE_PACKAGE] = package
    sys.modules[f"{FIXTURE_PACKAGE}.api"] = api_package
    common = _load_module(
        f"{FIXTURE_PACKAGE}.api.native_mcp_common",
        REPO_ROOT / "plugin/api/native_mcp_common.py",
    )
    inspection = _load_module(
        f"{FIXTURE_PACKAGE}.api.native_mcp_inspection",
        REPO_ROOT / "plugin/api/native_mcp_inspection.py",
    )
    return common, inspection


common, inspection = _load_native_modules()


class Named:
    def __init__(self, name: str):
        self.name = name

    def __str__(self):
        return self.name


class FakeSymbol:
    def __init__(
        self,
        name: str,
        address: int,
        symbol_type: str,
        binding: str = "GlobalBinding",
        full_name: str | None = None,
    ):
        self.name = name
        self.short_name = name
        self.full_name = full_name or name
        self.raw_name = name
        self.address = address
        self.type = Named(symbol_type)
        self.binding = Named(binding)
        self.namespace = ""
        self.ordinal = 0
        self.auto_defined = True


class FakeType:
    def __init__(self, text: str, type_class: str = "IntegerTypeClass"):
        self.text = text
        self.type_class = Named(type_class)
        self.width = 4
        self.alignment = 4
        self.confidence = 255
        if type_class == "StructureTypeClass":
            self.structure = types.SimpleNamespace(type=Named("StructStructureType"))

    def __str__(self):
        return self.text

    def get_lines(self, _bv, name, _padding=64, _collapsed=False):
        return [types.SimpleNamespace(tokens=[f"{self.text} {name}"])]


class FakeVariable:
    def __init__(self, name: str, storage: int, source: str = "StackVariableSourceType"):
        self.name = name
        self.storage = storage
        self.source_type = Named(source)
        self.index = abs(storage)
        self.identifier = 1000 + abs(storage)
        self.type = FakeType("int32_t")


class FakeInstruction:
    def __init__(self, address: int, text: str):
        self.address = address
        self.text = text

    def __str__(self):
        return self.text


class FakeIL:
    def __init__(self, instructions):
        self.instructions = list(instructions)
        self.ssa_form = self
        self.root = self.instructions[0] if self.instructions else None


class FakePseudoC:
    def get_linear_lines(self, root):
        return [
            types.SimpleNamespace(
                address=root.address,
                tokens=["int32_t pseudo_c_result() { return 7; }"],
            )
        ]


class FakeEdge:
    def __init__(self, source, target, branch_type="UnconditionalBranch"):
        self.source = source
        self.target = target
        self.type = Named(branch_type)
        self.back_edge = False
        self.fall_through = False


class FakeBlock:
    def __init__(self, index: int, start: int, end: int):
        self.index = index
        self.start = start
        self.end = end
        self.length = end - start
        self.arch = Named("aarch64")
        self.outgoing_edges = []


class FakeReference:
    def __init__(self, address: int, function=None):
        self.address = address
        self.function = function
        self.arch = Named("aarch64")


class FakeConvention(Named):
    pass


class FakePlatform(Named):
    def __init__(self):
        super().__init__("mac-aarch64")
        self.calling_conventions = [FakeConvention("cdecl"), FakeConvention("sysv")]
        self.default_calling_convention = self.calling_conventions[1]
        self.cdecl_calling_convention = self.calling_conventions[0]
        self.stdcall_calling_convention = None
        self.fastcall_calling_convention = None
        self.system_call_convention = None


class FakeFunction:
    def __init__(self, name: str, start: int, platform: FakePlatform):
        self.name = name
        self.start = start
        self.lowest_address = start
        self.highest_address = start + 8
        self.arch = Named("aarch64")
        self.platform = platform
        self.symbol = FakeSymbol(name, start, "FunctionSymbol")
        self.address_ranges = []
        self.analysis_skipped = False
        self.analysis_skip_reason = Named("NotSkipped")
        self.needs_update = False
        self.has_user_annotations = name == "entry"
        first = FakeBlock(0, start, start + 4)
        second = FakeBlock(1, start + 4, start + 8)
        first.outgoing_edges = [FakeEdge(first, second)]
        self.basic_blocks = [first, second]
        self.instructions = [(["mov x0, x1"], start), (["ret"], start + 4)]
        il = FakeIL([FakeInstruction(start, "x0 = x1"), FakeInstruction(start + 4, "return x0")])
        il.basic_blocks = self.basic_blocks
        self.lifted_il = il
        self.llil = il
        self.mlil = il
        self.hlil = il
        self.pseudo_c = FakePseudoC()
        self.vars = [
            FakeVariable("arg1", 0, "RegisterVariableSourceType"),
            FakeVariable("local", -8),
        ]
        self.parameter_vars = [self.vars[0]]
        self.stack_layout = [self.vars[1]]
        self.type = FakeType(f"int32_t {name}(int32_t arg1)", "FunctionTypeClass")
        self.return_type = FakeType("int32_t")
        self.calling_convention = platform.default_calling_convention
        self.has_explicitly_defined_type = True
        self.call_sites = []
        self.caller_sites = []
        self.reanalysis_count = 0

    def reanalyze(self):
        self.reanalysis_count += 1


class PendingFunction(FakeFunction):
    def __init__(self, name: str, start: int, platform: FakePlatform):
        self._hlil_reads = 0
        super().__init__(name, start, platform)
        self._hlil_reads = 0

    @property
    def hlil(self):
        self._hlil_reads += 1
        return self._hlil if self._hlil_reads >= 3 else None

    @hlil.setter
    def hlil(self, value):
        self._hlil = value


class FakeSegment:
    def __init__(self):
        self.start = 0x1000
        self.end = 0x3000
        self.length = 0x2000
        self.data_offset = 0
        self.data_length = 0x2000
        self.data_end = 0x2000
        self.readable = True
        self.writable = False
        self.executable = True
        self.auto_defined = True
        self.segment_info = types.SimpleNamespace(flags=Named("SegmentReadable|SegmentExecutable"))


class FakeSection:
    def __init__(self):
        self.name = "__text"
        self.start = 0x1000
        self.end = 0x1800
        self.length = 0x800
        self.semantics = Named("ReadOnlyCodeSectionSemantics")
        self.type = "regular"
        self.align = 4
        self.entry_size = 0
        self.linked_section = ""
        self.info_section = ""
        self.info_data = 0
        self.auto_defined = True


class FakeDataVariable:
    def __init__(self):
        self.address = 0x1800
        self.name = "global_value"
        self.type = FakeType("int32_t")
        self.auto_discovered = True
        self.symbol = FakeSymbol(self.name, self.address, "DataSymbol")


class FakeString:
    def __init__(self, start=0x1900, raw=b"hello\x00", value="hello"):
        self.start = start
        self.raw = raw
        self.value = value
        self.length = len(self.raw)
        self.type = Named("AsciiString")


class FakeRelocation:
    def __init__(self):
        self.reloc = 0x1810
        self.target = 0x2000
        self.arch = Named("aarch64")
        self.symbol = FakeSymbol("callee", 0x2000, "FunctionSymbol")
        self.info = types.SimpleNamespace(
            address=0x1810,
            target=0x2000,
            type=Named("StandardRelocationType"),
            native_type=2,
            size=8,
            addend=0,
            pc_relative=False,
            base_relative=False,
            external=True,
            data_relocation=True,
        )


class FakeTypeReference:
    def __init__(self):
        self.name = "Container"
        self.offset = 8
        self.ref_type = Named("DirectTypeReferenceType")


class FakeParsedTypes:
    def __init__(self):
        self.types = {"Parsed": FakeType("struct Parsed { int x; }", "StructureTypeClass")}
        self.variables = {"parsed_global": FakeType("int32_t")}
        self.functions = {"parsed_fn": FakeType("void parsed_fn(void)", "FunctionTypeClass")}
        self.errors = ""


class FakeView:
    def __init__(self):
        self.platform = FakePlatform()
        self.arch = Named("aarch64")
        self.entry = FakeFunction("entry", 0x1000, self.platform)
        self.callee = FakeFunction("callee", 0x2000, self.platform)
        self.entry.call_sites = [FakeReference(0x1004, self.entry)]
        self.entry.caller_sites = [FakeReference(0x2004, self.callee)]
        self.functions = [self.entry, self.callee]
        self.entry_functions = [self.entry]
        self.entry_function = self.entry
        self.entry_point = self.entry.start
        self.start = 0x1000
        self.end = 0x3000
        self.length = self.end - self.start
        self.view_type = "Mach-O"
        self.executable = True
        self.relocatable = False
        self.address_size = 8
        self.file = types.SimpleNamespace(filename="/fixtures/sample")
        self.segments = [FakeSegment()]
        self.sections = {"__text": FakeSection()}
        self._symbols = [
            self.entry.symbol,
            self.callee.symbol,
            FakeSymbol("_puts", 0x2800, "ImportedFunctionSymbol"),
            FakeSymbol("external", 0x2810, "ExternalSymbol"),
            FakeSymbol("weak_export", 0x2820, "DataSymbol", "WeakBinding"),
            FakeSymbol("local_only", 0x2830, "DataSymbol", "LocalBinding"),
            FakeSymbol("unbound", 0x2840, "DataSymbol", "NoBinding"),
            FakeSymbol("z_short", 0x2850, "DataSymbol", "LocalBinding", "a::full_name"),
            FakeSymbol("a_short", 0x2850, "DataSymbol", "LocalBinding", "z::full_name"),
        ]
        self.data_variable = FakeDataVariable()
        self.data_vars = {self.data_variable.address: self.data_variable}
        self.strings = [FakeString()]
        self.relocations = [FakeRelocation()]
        self.types = {"Known": FakeType("struct Known { int member; }", "StructureTypeClass")}
        self.analysis_state = Named("IdleState")
        self.analysis_is_aborted = False
        active = types.SimpleNamespace(
            func=self.entry,
            analysis_time=5,
            update_count=2,
            submit_count=1,
        )
        self.analysis_info = types.SimpleNamespace(
            state=Named("IdleState"), analysis_time=10, active_info=[active]
        )
        self.analysis_progress = types.SimpleNamespace(state=Named("IdleState"), count=4, total=4)
        self.update_count = 0
        self.wait_count = 0
        self.abort_count = 0
        self.get_strings_calls = []

    def parse_expression(self, expression: str):
        names = {"entry": 0x1000, "callee": 0x2000, "global_value": 0x1800}
        if expression in names:
            return names[expression]
        if "+" in expression:
            left, right = (part.strip() for part in expression.split("+", 1))
            return names[left] + int(right, 0)
        if expression.lower().startswith("0n"):
            return int(expression[2:], 10)
        return int(expression, 0)

    def get_functions_at(self, address: int):
        return [function for function in self.functions if function.start == address]

    def get_function_at(self, address: int):
        matches = self.get_functions_at(address)
        return matches[0] if matches else None

    def get_functions_containing(self, address: int):
        return [
            function
            for function in self.functions
            if function.lowest_address <= address <= function.highest_address
        ]

    def get_symbols(self, start=None, length=None):
        if start is not None:
            end = start + (1 if length is None else length)
            return [symbol for symbol in self._symbols if start <= symbol.address < end]
        return list(self._symbols)

    def get_symbol_at(self, address: int):
        return next((symbol for symbol in self._symbols if symbol.address == address), None)

    def update_analysis(self):
        self.update_count += 1

    def update_analysis_and_wait(self):
        self.wait_count += 1

    def abort_analysis(self):
        self.abort_count += 1
        self.analysis_is_aborted = True

    def read(self, address: int, length: int):
        if address == 0x1000:
            data = b"ABCD"
        else:
            string = next((item for item in self.strings if item.start == address), None)
            data = string.raw if string is not None else b""
        return data[:length]

    def get_strings(self, start: int, length: int):
        self.get_strings_calls.append((start, length))
        end = start + length
        return [string for string in self.strings if start <= string.start < end]

    def get_data_refs(self, address: int, length=None):
        return iter([0x1810])

    def get_data_refs_from(self, address: int, length=None):
        return iter([0x2000])

    def get_callers(self, address: int):
        return iter(self.entry.caller_sites)

    def get_callees(self, address: int, function=None, arch=None):
        return [0x2000] if address == 0x1004 else []

    def get_code_refs(self, address: int):
        return iter([*self.entry.caller_sites, FakeReference(0x2008, self.callee)])

    def get_code_refs_from(self, address: int, function=None, arch=None):
        if address == 0x1000:
            return [0x2800]
        if address == 0x1004:
            return [0x2000]
        return []

    def get_comment_at(self, address: int):
        return "entry comment" if address == 0x1000 else ""

    def get_type_by_name(self, name: str):
        return self.types.get(name)

    def get_type_id(self, name):
        return f"type-id:{name}"

    def is_type_auto_defined(self, name):
        return str(name) == "Known"

    def parse_types_from_string(self, source, options, include_dirs, import_dependencies):
        if "invalid" in source:
            raise SyntaxError("bad declaration")
        return FakeParsedTypes()

    def get_code_refs_for_type(self, name, max_items=None):
        return iter([FakeReference(0x1000, self.entry)])

    def get_data_refs_for_type(self, name, max_items=None):
        return iter([0x1800])

    def get_type_refs_for_type(self, name, max_items=None):
        return [FakeTypeReference()]

    def get_outgoing_direct_type_references(self, name):
        return ["Dependency"]

    def get_incoming_direct_type_references(self, name):
        return ["Container"]

    def get_outgoing_recursive_type_references(self, name):
        return ["Dependency", "NestedDependency"]

    def get_sections_at(self, address: int):
        return [self.sections["__text"]] if address < 0x1800 else []

    def get_segment_at(self, address: int):
        return self.segments[0] if self.start <= address < self.end else None

    def get_data_var_at(self, address: int):
        return self.data_variable if address == self.data_variable.address else None

    def get_string_at(self, address: int, partial=False):
        string = self.strings[0]
        if string.start <= address < string.start + string.length:
            return string
        return None

    def is_valid_offset(self, address: int):
        return self.start <= address < self.end

    def is_offset_readable(self, address: int):
        return self.is_valid_offset(address)

    def is_offset_writable(self, address: int):
        return False

    def is_offset_executable(self, address: int):
        return 0x1000 <= address < 0x1800


class NativeMcpCommonTests(unittest.TestCase):
    def test_expression_and_pagination_contract(self):
        view = FakeView()
        self.assertEqual(common.parse_address(view, "entry + 0x10"), 0x1010)
        page = common.paginate(range(5), {"offset": 1, "limit": 2}, item_key="values")
        self.assertEqual(page["values"], [1, 2])
        self.assertEqual(page["count"], 2)
        self.assertEqual(page["total"], 5)
        self.assertEqual(page["nextOffset"], 3)
        self.assertTrue(page["truncated"])

    def test_errors_are_stable_and_json_safe(self):
        error = common.NativeMcpError("invalid_params", "bad", {"payload": b"x"})
        encoded = json.dumps(error.to_dict())
        self.assertIn("invalid_params", encoded)
        with self.assertRaises(common.NativeMcpError) as raised:
            common.parse_integer(True, "limit")
        self.assertEqual(raised.exception.code, "invalid_params")


class NativeMcpInspectionTests(unittest.TestCase):
    def setUp(self):
        self.view = FakeView()

    def dispatch(self, tool, args=None):
        result = inspection.dispatch_inspection(tool, args or {}, self.view)
        json.dumps(result)
        return result

    def test_catalog_matches_requested_native_read_tools(self):
        expected = {
            "bn_analysis_abort",
            "bn_analysis_status",
            "bn_analysis_update",
            "bn_analysis_update_and_wait",
            "bn_binary_view_triage",
            "bn_calling_convention_list",
            "bn_comment_get",
            "bn_data_at",
            "bn_data_variable_list",
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
            "bn_function_search",
            "bn_function_stack_layout",
            "bn_function_xrefs_from",
            "bn_function_xrefs_to",
            "bn_import_list",
            "bn_memory_read",
            "bn_relocation_list",
            "bn_section_list",
            "bn_segment_list",
            "bn_string_list",
            "bn_symbol_list",
            "bn_symbol_list_at",
            "bn_type_info",
            "bn_type_list",
            "bn_type_parse",
            "bn_type_search",
            "bn_type_xrefs_from",
            "bn_type_xrefs_to",
            "bn_variable_list",
        }
        self.assertEqual(inspection.INSPECTION_TOOLS, expected)

    def test_all_registered_operations_return_json_safe_results(self):
        calls = {
            "bn_analysis_abort": {},
            "bn_analysis_status": {},
            "bn_analysis_update": {},
            "bn_analysis_update_and_wait": {},
            "bn_binary_view_triage": {},
            "bn_calling_convention_list": {"function": "entry"},
            "bn_comment_get": {"comment": "entry"},
            "bn_data_at": {"address": "global_value"},
            "bn_data_variable_list": {},
            "bn_data_xrefs_from": {"address": "global_value"},
            "bn_data_xrefs_to": {"address": "callee"},
            "bn_entry_point_list": {},
            "bn_export_list": {},
            "bn_function_basic_blocks": {"function": "entry"},
            "bn_function_callees": {"function": "entry"},
            "bn_function_callers": {"function": "entry"},
            "bn_function_complexity": {"function": "entry"},
            "bn_function_decompile": {"function": "entry"},
            "bn_function_disassembly": {"function": "entry"},
            "bn_function_il": {"function": "entry", "level": "mlil", "ssa": True},
            "bn_function_info": {"function": "entry"},
            "bn_function_list": {},
            "bn_function_prototype_get": {"function": "entry"},
            "bn_function_search": {"query": "try"},
            "bn_function_stack_layout": {"function": "entry"},
            "bn_function_xrefs_from": {"function": "entry"},
            "bn_function_xrefs_to": {"function": "entry"},
            "bn_import_list": {},
            "bn_memory_read": {"address": "entry", "length": 4},
            "bn_relocation_list": {},
            "bn_section_list": {},
            "bn_segment_list": {},
            "bn_string_list": {"previewBytes": 3},
            "bn_symbol_list": {},
            "bn_symbol_list_at": {"address": "entry"},
            "bn_type_info": {"type": "Known"},
            "bn_type_list": {},
            "bn_type_parse": {"source": "struct Parsed { int x; };"},
            "bn_type_search": {"query": "know"},
            "bn_type_xrefs_from": {"type": "Known", "recursive": True},
            "bn_type_xrefs_to": {"type": "Known", "maxItems": 10},
            "bn_variable_list": {"function": "entry"},
        }
        for tool, args in calls.items():
            with self.subTest(tool=tool):
                self.dispatch(tool, args)

        self.assertEqual(self.view.update_count, 1)
        self.assertEqual(self.view.wait_count, 1)
        self.assertEqual(self.view.abort_count, 1)

    def test_native_pagination_and_function_search(self):
        result = self.dispatch("bn_function_list", {"offset": 1, "limit": 1})
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["functions"][0]["address"], "0x2000")
        searched = self.dispatch("bn_function_search", {"query": "TRY"})
        self.assertEqual([item["name"] for item in searched["functions"]], ["entry"])
        default_arch = self.dispatch("bn_function_info", {"function": "entry", "arch": ""})
        self.assertEqual(default_arch["function"]["address"], "0x1000")
        symbols = self.dispatch("bn_symbol_list")
        self.assertTrue(symbols["symbols"][0]["autoDefined"])
        known_type = self.dispatch("bn_type_info", {"type": "Known"})
        self.assertEqual(known_type["type"], "Known")
        self.assertEqual(known_type["id"], "type-id:Known")
        self.assertTrue(known_type["autoDefined"])
        self.assertEqual(known_type["structureType"], "StructStructureType")
        self.assertEqual(known_type["source"], "struct Known { int member; } Known\n")
        self.assertEqual(known_type["outgoingDirectTypeReferences"], ["Dependency"])
        self.assertEqual(known_type["incomingDirectTypeReferences"], ["Container"])

    def test_import_and_export_symbol_filters_match_native_binding_rules(self):
        imports = self.dispatch("bn_import_list", {"limit": 100})["imports"]
        self.assertEqual([item["name"] for item in imports], ["_puts"])
        self.assertEqual(self.dispatch("bn_import_list", {"query": "GlobalBinding"})["total"], 0)
        self.assertEqual(self.dispatch("bn_import_list", {"query": "PUTS"})["total"], 1)
        exports = self.dispatch("bn_export_list", {"limit": 100})["exports"]
        self.assertEqual(
            {item["name"] for item in exports},
            {"entry", "callee", "external", "weak_export"},
        )
        self.assertEqual(self.dispatch("bn_export_list", {"query": "GlobalBinding"})["total"], 0)
        same_address = self.dispatch(
            "bn_symbol_list", {"start": "0x2850", "length": 1, "limit": 10}
        )["symbols"]
        self.assertEqual([item["name"] for item in same_address], ["z_short", "a_short"])

    def test_memory_read_encodings_partial_result_and_cap(self):
        result = self.dispatch("bn_memory_read", {"address": "entry", "length": 8})
        self.assertEqual(result["hex"], "41424344")
        self.assertEqual(result["base64"], "QUJDRA==")
        self.assertEqual(result["bytesRead"], 4)
        self.assertTrue(result["partial"])
        with self.assertRaises(common.NativeMcpError) as raised:
            self.dispatch("bn_memory_read", {"address": "entry", "length": 65537})
        self.assertEqual(raised.exception.code, "invalid_params")

    def test_string_query_is_independent_of_preview_and_scan_is_bounded(self):
        result = self.dispatch("bn_string_list", {"query": "HELLO", "previewBytes": 0, "limit": 1})
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["strings"][0]["value"], "")
        self.assertEqual(result["strings"][0]["previewHex"], "")
        self.assertEqual(self.view.get_strings_calls, [(0x1000, 0x2000)])

        self.view.get_strings_calls.clear()
        self.view.segments = [types.SimpleNamespace(start=0, end=(3 << 20) + 1)]
        self.view.start = 0
        self.view.end = (3 << 20) + 1
        self.view.strings = [
            FakeString(start=index << 20, raw=f"item-{index}\x00".encode(), value=f"item-{index}")
            for index in range(4)
        ]
        page = self.dispatch("bn_string_list", {"offset": 1, "limit": 2})
        self.assertEqual(page["total"], 4)
        self.assertEqual([item["value"] for item in page["strings"]], ["item-1", "item-2"])
        self.assertGreaterEqual(len(self.view.get_strings_calls), 4)
        self.assertTrue(
            all(
                length <= inspection._STRING_SCAN_CHUNK_BYTES
                for _, length in self.view.get_strings_calls
            )
        )

    def test_disassembly_il_and_complexity_are_structured(self):
        disassembly = self.dispatch("bn_function_disassembly", {"function": "entry"})
        self.assertEqual(disassembly["lines"][0], {"address": "0x1000", "text": "mov x0, x1"})
        self.view.entry.analysis_skipped = True
        decompile = self.dispatch("bn_function_decompile", {"function": "entry"})
        self.assertEqual(decompile["language"], "Pseudo C")
        self.assertTrue(decompile["analysisEnabledOnDemand"])
        self.assertFalse(self.view.entry.analysis_skipped)
        self.assertEqual(self.view.entry.reanalysis_count, 1)
        self.assertIn("pseudo_c_result", decompile["text"])
        self.assertNotIn("x0 = x1", decompile["text"])
        il = self.dispatch("bn_function_il", {"function": "entry", "level": "hlil", "ssa": True})
        self.assertEqual(il["level"], "hlil")
        self.assertIn("return x0", il["text"])
        complexity = self.dispatch("bn_function_complexity", {"function": "entry"})
        self.assertEqual(complexity["basicBlockCount"], 2)
        self.assertEqual(complexity["edgeCount"], 1)
        self.assertEqual(complexity["cyclomaticComplexity"], 1)
        self.assertEqual(complexity["blocks"], 2)
        self.assertEqual(complexity["calls"], 1)
        self.assertEqual(complexity["variables"], 2)
        self.assertEqual(complexity["mlilSsaEdgeCount"], 1)
        self.assertEqual(
            [metric["metric"] for metric in complexity["metrics"]],
            ["Blocks", "Edges", "Calls", "Variables", "MLIL SSA Edge Count"],
        )

        self.view.entry.needs_update = True
        warning_result = self.dispatch("bn_function_il", {"function": "entry"})
        self.assertEqual(warning_result["warnings"][0]["code"], "function_needs_update")

    def test_non_skipped_pending_function_artifact_is_requested_and_waited_for(self):
        pending = PendingFunction("entry", 0x1000, self.view.platform)
        self.view.entry = pending
        self.view.functions[0] = pending
        result = self.dispatch("bn_function_il", {"function": "entry", "level": "hlil"})
        self.assertIn("return x0", result["text"])
        self.assertTrue(result["analysisEnabledOnDemand"])
        self.assertEqual(pending.reanalysis_count, 1)

    def test_type_parse_failures_and_dispatch_errors_are_domain_errors(self):
        with self.assertRaises(common.NativeMcpError) as parse_error:
            self.dispatch("bn_type_parse", {"source": "invalid"})
        self.assertEqual(parse_error.exception.code, "type_parse_failed")
        with self.assertRaises(common.NativeMcpError) as unknown:
            self.dispatch("bn_does_not_exist")
        self.assertEqual(unknown.exception.code, "unknown_tool")
        with self.assertRaises(common.NativeMcpError) as no_view:
            inspection.dispatch_inspection("bn_analysis_status", {}, None)
        self.assertEqual(no_view.exception.code, "no_active_binary_view")


if __name__ == "__main__":
    unittest.main()
