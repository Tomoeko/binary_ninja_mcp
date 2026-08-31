import assert from "node:assert/strict";
import test from "node:test";

import { McpServer, RegisteredTool } from "@modelcontextprotocol/sdk/server/mcp.js";
import { AxiosHeaders, AxiosRequestConfig, AxiosResponse } from "axios";

import {
  BinjaHttpClient,
  buildRequestHeaders,
  withBinaryTarget,
} from "../src/client.js";
import { registerTools } from "../src/tools.js";

type RegisteredTools = Record<string, RegisteredTool>;

function decodedTarget(headers: Record<string, string>): string {
  const encoded = headers["X-Binary-Ninja-View-B64"] || "";
  return encoded ? Buffer.from(encoded, "base64").toString("utf8") : "";
}

function registeredTools(server: McpServer): RegisteredTools {
  return (server as unknown as { _registeredTools: RegisteredTools })._registeredTools;
}

function inputShape(tool: RegisteredTool): Record<string, unknown> {
  const schema = tool.inputSchema as Record<string, unknown> & {
    shape?: Record<string, unknown>;
  };
  return schema.shape || schema;
}

test("target-dependent tools expose binary while management tools stay compatible", () => {
  const server = new McpServer({ name: "targeting-test", version: "1" });
  registerTools(server, {} as BinjaHttpClient);
  const tools = registeredTools(server);

  const decompileSchema = inputShape(tools.decompile_function);
  assert.ok(decompileSchema.binary);
  for (const name of [
    "close_binary",
    "open_binary",
    "list_binaries",
    "select_binary",
    "convert_number",
    "list_platforms",
  ]) {
    const schema = inputShape(tools[name]);
    assert.equal(schema.binary, undefined, `${name} should not require a BinaryView`);
  }
});

test("concurrent tool handlers retain independent binary selectors", async () => {
  const observed: string[] = [];
  const fakeClient = {
    async getJson(endpoint: string): Promise<Record<string, string>> {
      await new Promise<void>((resolve) => setImmediate(resolve));
      const binary = decodedTarget(buildRequestHeaders());
      observed.push(`${endpoint}:${binary}`);
      if (endpoint === "status") {
        return { filename: binary };
      }
      return { decompiled: binary };
    },
  } as BinjaHttpClient;

  const server = new McpServer({ name: "targeting-test", version: "1" });
  registerTools(server, fakeClient);
  const handler = registeredTools(server).decompile_function.handler as (
    args: Record<string, string>,
    extra: Record<string, never>,
  ) => Promise<{ content: Array<{ text: string }> }>;

  const [left, right] = await Promise.all([
    handler({ name: "target", binary: "view-a" }, {}),
    handler({ name: "target", binary: "view-b" }, {}),
  ]);

  assert.match(left.content[0].text, /view-a/);
  assert.match(right.content[0].text, /view-b/);
  assert.deepEqual(
    observed.sort(),
    ["decompile:view-a", "decompile:view-b", "status:view-a", "status:view-b"],
  );
  assert.equal(buildRequestHeaders()["X-Binary-Ninja-View-B64"], undefined);
});

test("the HTTP client attaches authentication and target headers to every verb", async () => {
  const captured: AxiosRequestConfig[] = [];
  const client = new BinjaHttpClient({
    host: "127.0.0.1",
    port: 45678,
    authToken: "secret-token",
  });
  const axiosClient = (
    client as unknown as {
      client: {
        defaults: {
          adapter: (config: AxiosRequestConfig) => Promise<AxiosResponse>;
        };
      };
    }
  ).client;
  axiosClient.defaults.adapter = async (config) => {
    captured.push(config);
    const isJson = config.url === "json";
    return {
      config,
      data: isJson ? {} : "ok",
      headers: {},
      status: 200,
      statusText: "OK",
    };
  };

  await withBinaryTarget("view:π/分析", async () => {
    await client.getJson("json");
    await client.getText("text");
    await client.post("post-json", { value: 1 });
    await client.post("post-text", "value");
    await client.delete("delete");
  });

  assert.equal(captured.length, 5);
  for (const config of captured) {
    const headers = AxiosHeaders.from(config.headers);
    assert.equal(headers.get("X-Binary-Ninja-MCP-Token"), "secret-token");
    assert.equal(
      Buffer.from(String(headers.get("X-Binary-Ninja-View-B64")), "base64").toString("utf8"),
      "view:π/分析",
    );
  }
  assert.equal(axiosClient.defaults.proxy, false);
  assert.equal(axiosClient.defaults.timeout, 0);
});
