/**
 * HTTP client for communicating with the Binary Ninja MCP server.
 */

import { AsyncLocalStorage } from "node:async_hooks";

import axios, { AxiosInstance, AxiosResponse } from "axios";

export interface BinjaServerConfig {
  host: string;
  port: number;
  authToken?: string;
}

interface BinjaRequestScope {
  binary: string;
}

const requestScope = new AsyncLocalStorage<BinjaRequestScope>();

/** Run one tool invocation with an immutable, async-local binary selector. */
export function withBinaryTarget<T>(binary: string, operation: () => T): T {
  const target = binary.trim();
  if (!target) {
    return operation();
  }
  return requestScope.run({ binary: target }, operation);
}

/** Build the headers shared by every HTTP verb for the current tool invocation. */
export function buildRequestHeaders(authToken: string = ""): Record<string, string> {
  const headers: Record<string, string> = {};
  if (authToken) {
    headers["X-Binary-Ninja-MCP-Token"] = authToken;
  }
  const binary = requestScope.getStore()?.binary;
  if (binary) {
    headers["X-Binary-Ninja-View-B64"] = Buffer.from(binary, "utf8").toString("base64");
  }
  return headers;
}

export class BinjaHttpClient {
  private client: AxiosInstance;
  private baseUrl: string;
  private authToken: string;

  constructor(config: BinjaServerConfig) {
    this.baseUrl = `http://${config.host}:${config.port}`;
    this.authToken = config.authToken || "";
    this.client = axios.create({
      baseURL: this.baseUrl,
      // Local authenticated traffic must never inherit HTTP_PROXY/ALL_PROXY.
      proxy: false,
      // A timed-out mutating request may remain queued in the host and execute
      // later. Wait for the authoritative response unless a caller supplies a
      // timeout for a known read-only operation.
      timeout: 0,
    });
  }

  /**
   * Perform a GET request and return raw text.
   */
  async getText(endpoint: string, params: Record<string, string | number> = {}, timeout?: number): Promise<string> {
    try {
      const response = await this.client.get(endpoint, {
        headers: buildRequestHeaders(this.authToken),
        params,
        timeout,
        responseType: "text",
      });
      if (response.status >= 200 && response.status < 300) {
        return response.data as string;
      }
      return `Error ${response.status}: ${response.data}`;
    } catch (error) {
      return this.handleError(error, "GET", endpoint);
    }
  }

  /**
   * Perform a GET request and return parsed JSON.
   */
  async getJson<T = unknown>(endpoint: string, params: Record<string, string | number> = {}, timeout?: number): Promise<T | { error: string }> {
    try {
      const response = await this.client.get(endpoint, {
        headers: buildRequestHeaders(this.authToken),
        params,
        timeout,
      });
      response.data as T;
      if (response.status >= 200 && response.status < 300) {
        return response.data as T;
      }
      // Non-OK: return parsed error object if available
      if (response.data && typeof response.data === "object" && "error" in response.data) {
        return response.data as T;
      }
      return { error: `Error ${response.status}: ${response.statusText}` };
    } catch (error) {
      const errorMsg = this.getErrorMessage(error);
      return { error: `Request failed: ${errorMsg}` };
    }
  }

  /**
   * Perform a GET request and return lines of text.
   */
  async getLines(endpoint: string, params: Record<string, string | number> = {}, timeout?: number): Promise<string[]> {
    const text = await this.getText(endpoint, params, timeout);
    return text.split("\n");
  }

  /**
   * Perform a POST request.
   */
  async post(endpoint: string, data: Record<string, unknown> | string): Promise<string> {
    try {
      let response: AxiosResponse<string>;
      if (typeof data === "string") {
        response = await this.client.post(endpoint, data, {
          headers: {
            ...buildRequestHeaders(this.authToken),
            "Content-Type": "text/plain",
          },
          responseType: "text",
        });
      } else {
        response = await this.client.post(endpoint, data, {
          headers: buildRequestHeaders(this.authToken),
          responseType: "text",
        });
      }
      if (response.status >= 200 && response.status < 300) {
        return response.data.trim();
      }
      return `Error ${response.status}: ${response.data}`;
    } catch (error) {
      return this.handleError(error, "POST", endpoint);
    }
  }

  /**
   * Perform a DELETE request with query parameters.
   */
  async delete(endpoint: string, params: Record<string, string | number> = {}): Promise<string> {
    try {
      const response = await this.client.delete<string>(endpoint, {
        headers: buildRequestHeaders(this.authToken),
        params,
        responseType: "text",
      });
      if (response.status >= 200 && response.status < 300) {
        return response.data.trim();
      }
      return `Error ${response.status}: ${response.data}`;
    } catch (error) {
      return this.handleError(error, "DELETE", endpoint);
    }
  }

  private handleError(error: unknown, method: string, endpoint: string): string {
    const msg = this.getErrorMessage(error);
    return `Error: ${method} ${endpoint} failed: ${msg}`;
  }

  private getErrorMessage(error: unknown): string {
    if (axios.isAxiosError(error)) {
      if (error.response) {
        return `Server returned ${error.response.status}: ${error.response.statusText}`;
      }
      if (error.request) {
        return "No response from server - is Binary Ninja running with the MCP plugin?";
      }
      return error.message;
    }
    return String(error);
  }
}

export function createClient(
  host: string = "localhost",
  port: number = 9009,
  authToken: string = "",
): BinjaHttpClient {
  return new BinjaHttpClient({ host, port, authToken });
}
