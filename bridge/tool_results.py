"""Readable MCP text alongside unchanged machine-readable tool results."""

from __future__ import annotations

import json

from mcp.types import CallToolResult


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(value: str) -> object:
    raise ValueError("Non-JSON constant: " + value)


def _presentation_value(value: object) -> object:
    if not isinstance(value, str) or not value.lstrip().startswith(("{", "[")):
        return value
    try:
        return json.loads(value, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, RecursionError):
        return value


def _duplicate_body(value: dict) -> bool:
    text = value.get("text")
    lines = value.get("lines")
    return (
        isinstance(text, str)
        and isinstance(lines, list)
        and all(isinstance(line, dict) and isinstance(line.get("text"), str) for line in lines)
        and text == "\n".join(line["text"] for line in lines)
    )


def _render(value: object, indent: str = "") -> list[str]:
    if isinstance(value, dict):
        if not value:
            return [indent + "(empty object)"]
        rendered = []
        duplicate_body = _duplicate_body(value)
        for key, child in value.items():
            label = indent + str(key) + ":"
            if key == "lines" and duplicate_body:
                rendered.append(label + f" {len(child)} entries (body shown in text)")
            elif isinstance(child, (dict, list)):
                rendered.append(label)
                rendered.extend(_render(child, indent + "  "))
            elif isinstance(child, str) and "\n" in child:
                # Keep code and other multiline strings readable without JSON escaping.
                rendered.extend((label, child))
            else:
                rendered.append(label + " " + _render(child)[0])
        return rendered
    if isinstance(value, list):
        if not value:
            return [indent + "(empty list)"]
        rendered = []
        for child in value:
            lines = _render(child, indent + "  ")
            rendered.append(indent + "- " + lines[0][len(indent) + 2 :])
            rendered.extend(lines[1:])
        return rendered
    if value is None:
        text = "(none)"
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, str):
        text = value if value else "(empty string)"
    else:
        text = str(value)
    return [indent + text]


def _readable(name: str, value: object) -> str:
    header = name + "\n\n"
    if isinstance(value, str) and value.startswith(header):
        return value
    return header + "\n".join(_render(_presentation_value(value)))


def tool_result(name: str, value: object) -> CallToolResult:
    """Preserve the result value and give text clients a distinct readable block.

    Wire aliases work with both SDK naming conventions. Existing result envelopes
    retain their flags, metadata, structured payload and non-text content blocks.
    This function does not infer success or failure from a payload's wording.
    """
    if not isinstance(value, CallToolResult):
        structured = value if isinstance(value, dict) else {"result": value}
        return CallToolResult.model_validate(
            {
                "content": [{"type": "text", "text": _readable(name, value)}],
                "structuredContent": structured,
            }
        )

    payload = value.model_dump(by_alias=True)
    content = []
    has_text = False
    for block in payload["content"]:
        if block["type"] == "text":
            block = {**block, "text": _readable(name, block["text"])}
            has_text = True
        content.append(block)
    if not has_text:
        display = payload.get("structuredContent")
        if display is None and content:
            display = f"{len(content)} non-text content item(s)."
        content.insert(0, {"type": "text", "text": _readable(name, display)})
    return CallToolResult.model_validate({**payload, "content": content})
