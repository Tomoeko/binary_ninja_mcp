from __future__ import annotations

import copy
import json
import unittest

from mcp.types import CallToolResult

from bridge.tool_results import tool_result


def wire(value):
    return value.model_dump(by_alias=True)


class ToolResultTests(unittest.TestCase):
    def test_native_code_is_readable_once_and_structured_lines_are_preserved(self):
        body = "int entry(int value)\n{\n    return value + 1;\n}"
        source = {
            "function": {"address": "0x1000", "name": "entry"},
            "language": "Pseudo C",
            "text": body,
            "lines": [
                {"address": hex(0x1000 + index), "text": line}
                for index, line in enumerate(body.split("\n"))
            ],
            "warnings": [{"code": "function_needs_update", "message": "Analysis is pending."}],
        }
        original = copy.deepcopy(source)
        result = wire(tool_result("bn_function_decompile", source))
        text = result["content"][0]["text"]
        self.assertTrue(text.startswith("bn_function_decompile\n\n"))
        self.assertIn(body, text)
        self.assertEqual(text.count("return value + 1;"), 1)
        self.assertIn("lines: 4 entries (body shown in text)", text)
        self.assertIn("function_needs_update", text)
        self.assertEqual(result["structuredContent"], original)
        self.assertEqual(source, original)
        self.assertFalse(result["isError"])
        with self.assertRaises(json.JSONDecodeError):
            json.loads(text)

    def test_distinct_line_text_is_not_suppressed(self):
        result = wire(
            tool_result(
                "bn_function_il",
                {
                    "text": "return value;",
                    "lines": [{"address": "0x1000", "text": "value = 1;"}],
                },
            )
        )
        text = result["content"][0]["text"]
        self.assertIn("return value;", text)
        self.assertIn("value = 1;", text)
        self.assertNotIn("body shown in text", text)

    def test_native_status_keeps_zero_false_none_and_nested_values(self):
        value = {
            "state": "IdleState",
            "analysisTime": 0,
            "aborted": False,
            "progress": {"count": 0, "total": 0},
            "active": [],
            "detail": None,
        }
        result = wire(tool_result("bn_analysis_status", value))
        text = result["content"][0]["text"]
        for expected in [
            "state: IdleState",
            "analysisTime: 0",
            "aborted: false",
            "count: 0",
            "(empty list)",
            "detail: (none)",
        ]:
            self.assertIn(expected, text)
        self.assertEqual(result["structuredContent"], value)

    def test_nested_lists_and_unicode_keep_the_complete_original_payload(self):
        value = [{"name": "函数π", "nested": [1, False, ["line one\nline two", None]]}]
        result = wire(tool_result("list_items", value))
        self.assertEqual(result["structuredContent"], {"result": value})
        text = result["content"][0]["text"]
        for expected in ["函数π", "line one\nline two", "false", "(none)"]:
            self.assertIn(expected, text)
        self.assertNotIn("\\u", text)

    def test_legacy_json_is_parsed_only_for_presentation(self):
        value = ' { "state" : "IdleState", "active": [] }\n'
        result = wire(tool_result("get_binary_status", value))
        self.assertEqual(result["structuredContent"], {"result": value})
        self.assertIn("state: IdleState", result["content"][0]["text"])
        self.assertNotIn('"state"', result["content"][0]["text"])

    def test_plain_strings_keep_their_literal_text(self):
        value = "Binary closed: view:7"
        result = wire(tool_result("close_binary", value))
        self.assertEqual(result["structuredContent"], {"result": value})
        self.assertEqual(result["content"][0]["text"], "close_binary\n\n" + value)

    def test_ambiguous_or_invalid_legacy_json_stays_literal(self):
        for value in ['{"state":1,"state":2}', '{"value":NaN}', "{broken", "[1,]"]:
            with self.subTest(value=value):
                result = wire(tool_result("legacy", value))
                self.assertEqual(result["structuredContent"], {"result": value})
                self.assertEqual(result["content"][0]["text"], "legacy\n\n" + value)

    def test_empty_results_and_scalar_wrappers_are_explicit(self):
        for value, expected in [
            ({}, "(empty object)"),
            ([], "(empty list)"),
            ("", "(empty string)"),
            (None, "(none)"),
            (0, "0"),
            (False, "false"),
            (1.25, "1.25"),
        ]:
            with self.subTest(value=value):
                result = wire(tool_result("result", value))
                self.assertEqual(result["content"][0]["text"], "result\n\n" + expected)
                self.assertEqual(
                    result["structuredContent"],
                    value if isinstance(value, dict) else {"result": value},
                )

    def test_error_wording_does_not_invent_protocol_failure(self):
        for value in ["Error: supplied text", {"error": "payload data"}]:
            with self.subTest(value=value):
                self.assertFalse(wire(tool_result("inspect", value))["isError"])

    def test_existing_error_envelope_metadata_and_nontext_items_survive(self):
        original = CallToolResult.model_validate(
            {
                "isError": True,
                "_meta": {"trace": "original"},
                "structuredContent": {"error": {"code": "unavailable", "message": "Missing data"}},
                "content": [
                    {
                        "type": "text",
                        "text": "Missing data",
                        "_meta": {"part": 1},
                        "annotations": {"audience": ["user"], "priority": 0.5},
                    },
                    {
                        "type": "image",
                        "data": "AA==",
                        "mimeType": "image/png",
                        "_meta": {"origin": "unchanged"},
                    },
                    {"type": "text", "text": "Additional detail"},
                ],
            }
        )
        original_wire = wire(original)
        result = wire(tool_result("inspect", original))
        self.assertTrue(result["isError"])
        self.assertEqual(result["_meta"], original_wire["_meta"])
        self.assertEqual(result["structuredContent"], original_wire["structuredContent"])
        self.assertEqual(result["content"][1], original_wire["content"][1])
        self.assertEqual(
            result["content"][0]["annotations"], original_wire["content"][0]["annotations"]
        )
        self.assertEqual(result["content"][0]["_meta"], {"part": 1})
        self.assertEqual(result["content"][0]["text"], "inspect\n\nMissing data")
        self.assertEqual(result["content"][2]["text"], "inspect\n\nAdditional detail")
        self.assertEqual(wire(original), original_wire)
        self.assertEqual(wire(tool_result("inspect", tool_result("inspect", original))), result)

    def test_nontext_only_result_gets_a_header_without_losing_image(self):
        source = CallToolResult.model_validate(
            {
                "content": [{"type": "image", "data": "AA==", "mimeType": "image/png"}],
                "structuredContent": {"description": "preview"},
            }
        )
        result = wire(tool_result("preview", source))
        self.assertEqual(result["content"][1], wire(source)["content"][0])
        self.assertIn("description: preview", result["content"][0]["text"])
        self.assertEqual(result["structuredContent"], {"description": "preview"})

    def test_existing_native_json_text_becomes_readable_without_changing_payload(self):
        payload = {"state": "IdleState", "active": []}
        source = CallToolResult.model_validate(
            {
                "content": [{"type": "text", "text": json.dumps(payload)}],
                "structuredContent": payload,
            }
        )
        result = wire(tool_result("bn_analysis_status", source))
        self.assertEqual(result["structuredContent"], payload)
        self.assertIn("state: IdleState", result["content"][0]["text"])
        self.assertTrue(result["content"][0]["text"].startswith("bn_analysis_status\n\n"))
        self.assertFalse(result["isError"])

    def test_nontext_result_without_structured_data_stays_unstructured(self):
        source = CallToolResult.model_validate(
            {
                "content": [{"type": "image", "data": "AA==", "mimeType": "image/png"}],
            }
        )
        result = wire(tool_result("preview", source))
        self.assertEqual(result["content"][0]["text"], "preview\n\n1 non-text content item(s).")
        self.assertEqual(result["content"][1], wire(source)["content"][0])
        self.assertIsNone(result["structuredContent"])

    def test_existing_empty_result_keeps_absent_structured_payload(self):
        source = CallToolResult.model_validate({"content": []})
        result = wire(tool_result("empty", source))
        self.assertEqual(result["content"][0]["text"], "empty\n\n(none)")
        self.assertIsNone(result["structuredContent"])


if __name__ == "__main__":
    unittest.main()
