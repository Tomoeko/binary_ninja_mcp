"""Shared presentation of native and legacy MCP tool responses."""

from __future__ import annotations

from typing import Any

from mcp.types import CallToolResult, TextContent

try:
    from mcp.server.fastmcp import FastMCP
except ModuleNotFoundError:
    from mcp.server.mcpserver import MCPServer as FastMCP

try:
    from mcp.shared.exceptions import MCPError as ProtocolError
except ImportError:
    from mcp.shared.exceptions import McpError as ProtocolError

if __package__:
    from .tool_results import tool_result
else:
    from tool_results import tool_result


class BinaryNinjaMCP(FastMCP):
    """Present results after the SDK validates arguments and structured output."""

    async def call_tool(self, name: str, arguments: dict[str, Any], *args, **kwargs):
        try:
            result = await super().call_tool(name, arguments, *args, **kwargs)
        except ProtocolError:
            # Protocol errors carry their own JSON-RPC code and must retain it.
            raise
        except Exception as error:
            result = CallToolResult(
                content=[TextContent(type="text", text=str(error))],
                structuredContent={"error": {"message": str(error)}},
                isError=True,
            )

        # SDK 1.x returns content or a (content, structured data) pair. SDK 2.x
        # returns CallToolResult directly; normalize only the older forms.
        if isinstance(result, tuple):
            content, structured = result
            result = CallToolResult(content=list(content), structuredContent=structured)
        elif isinstance(result, list):
            result = CallToolResult(content=result)
        if isinstance(result, CallToolResult):
            return tool_result(name, result)
        # Keep SDK control-flow results (for example input requests) intact.
        return result
