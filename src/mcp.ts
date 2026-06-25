// MCP JSON-RPC surface for SIEMen.
// Mirrors the cf-memory-worker handler shape:
//   initialize, notifications/initialized, ping, tools/list, tools/call
// Error codes: -32700 (parse error / body too large), -32601 (method not found),
//              -32602 (invalid params), -32603 (internal error)
//
// tools/call dispatches to the same handler functions as REST routes — single source of truth.
// Mounted at POST /mcp in src/index.ts (behind verifyAuth middleware).

import type { Context } from "hono";
import type { Env, Variables, EngagementRecord } from "./types.js";
import { handleKvGet, handleKvSet } from "./handlers/kv.js";
import {
  handleEngagementOpen,
  handleEngagementReport,
  handleFindingStore,
  handleFindingBatch,
  handleFindingSearch,
  handleCacheStats,
} from "./handlers/findings.js";
import { handleRemember, handleRecall } from "./handlers/memory.js";
import { handleSemanticTriage } from "./cache.js";

type AppContext = { Bindings: Env; Variables: Variables };

/** MCP tool manifest — 12 tools. */
const TOOL_MANIFEST = [
  {
    name: "engagement_open",
    description: "Create or register a new pentest engagement. All other tools require an engagement_id.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Engagement name" },
        engagement_id: { type: "string", description: "Optional caller-supplied UUID" },
        client: { type: "string", description: "Client name (optional)" },
        status: { type: "string", enum: ["active", "closed", "archived"], description: "Engagement status" },
      },
      required: ["name"],
    },
  },
  {
    name: "engagement_list",
    description: "List all engagements. Optional status filter.",
    inputSchema: {
      type: "object",
      properties: {
        status: {
          type: "string",
          enum: ["active", "closed", "archived"],
          description: "Filter by engagement status (optional)",
        },
      },
    },
  },
  {
    name: "sec_cache_get",
    description: "Read a value from the fast K/V scratch store.",
    inputSchema: {
      type: "object",
      properties: {
        ns: { type: "string", description: "Namespace (scoped key prefix)" },
        key: { type: "string", description: "Key within namespace" },
      },
      required: ["ns", "key"],
    },
  },
  {
    name: "sec_cache_set",
    description: "Write a value to the fast K/V scratch store with optional TTL.",
    inputSchema: {
      type: "object",
      properties: {
        ns: { type: "string", description: "Namespace (scoped key prefix)" },
        key: { type: "string", description: "Key within namespace" },
        value: { type: "string", description: "Value to store" },
        ttl: { type: "integer", description: "TTL in seconds (max 86400)" },
      },
      required: ["ns", "key", "value"],
    },
  },
  {
    name: "finding_store",
    description: "Embed and store a security finding, CVE, or control in Vectorize + D1.",
    inputSchema: {
      type: "object",
      properties: {
        engagement_id: { type: "string" },
        kind: { type: "string", enum: ["finding", "cve", "control"] },
        title: { type: "string" },
        body: { type: "string" },
        severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
        asset: { type: "string", description: "Affected host/URL/component" },
        external_id: { type: "string", description: "e.g. CVE-2026-1234" },
        metadata: { type: "object", description: "Additional metadata JSON" },
        tags: { type: "array", items: { type: "string" }, description: "Tags for this finding" },
      },
      required: ["engagement_id", "kind", "title", "body"],
    },
  },
  {
    name: "finding_batch",
    description: "Batch ingest up to 100 findings/CVEs/controls in one call. Each item matches finding_store; a top-level engagement_id is inherited by items that omit it. Returns { stored, duplicates, errors }.",
    inputSchema: {
      type: "object",
      properties: {
        engagement_id: { type: "string", description: "Default engagement_id inherited by items that omit it" },
        findings: {
          type: "array",
          description: "Findings to ingest (max 100)",
          items: {
            type: "object",
            properties: {
              engagement_id: { type: "string" },
              kind: { type: "string", enum: ["finding", "cve", "control"] },
              title: { type: "string" },
              body: { type: "string" },
              severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
              asset: { type: "string", description: "Affected host/URL/component" },
              external_id: { type: "string", description: "e.g. CVE-2026-1234" },
              metadata: { type: "object", description: "Additional metadata JSON" },
              tags: { type: "array", items: { type: "string" } },
              cwe: { type: "string", description: "e.g. CWE-89" },
              owasp_category: { type: "string", description: "e.g. A03:2021-Injection" },
              cvss_v3: { type: "number", description: "CVSS v3 base score (0–10)" },
              epss: { type: "number", description: "EPSS probability (0–1)" },
              kev: { type: "integer", description: "1 if in CISA KEV catalog, else 0" },
            },
            required: ["kind", "title", "body"],
          },
        },
      },
      required: ["findings"],
    },
  },
  {
    name: "finding_search",
    description: "Semantic RAG over findings/CVEs/controls scoped to an engagement.",
    inputSchema: {
      type: "object",
      properties: {
        engagement_id: { type: "string" },
        query: { type: "string" },
        kind: { type: "string", enum: ["finding", "cve", "control"] },
        top_k: { type: "integer", description: "Max results (default 5, max 20)" },
      },
      required: ["engagement_id", "query"],
    },
  },
  {
    name: "engagement_remember",
    description: "Store agent memory for an engagement. Optionally enables vector recall.",
    inputSchema: {
      type: "object",
      properties: {
        engagement_id: { type: "string" },
        content: { type: "string" },
        session_id: { type: "string", description: "Optional sub-scope within an engagement" },
        tags: { type: "array", items: { type: "string" } },
        vector_recall: { type: "boolean", description: "Embed for semantic recall (default false)" },
      },
      required: ["engagement_id", "content"],
    },
  },
  {
    name: "engagement_recall",
    description: "Recall agent memories by engagement (recency or vector similarity). Pass query for semantic search.",
    inputSchema: {
      type: "object",
      properties: {
        engagement_id: { type: "string" },
        query: { type: "string", description: "Optional — triggers vector similarity recall when provided" },
        session_id: { type: "string" },
        top_k: { type: "integer" },
        vector_recall: { type: "boolean", description: "Use vector similarity instead of recency" },
      },
      required: ["engagement_id"],
    },
  },
  {
    name: "semantic_triage",
    description: "Semantic-cache-backed LLM triage. Returns cached analysis on hit; calls LLM on miss.",
    inputSchema: {
      type: "object",
      properties: {
        engagement_id: { type: "string" },
        prompt: { type: "string" },
        threshold: { type: "number", description: "Cosine threshold [0.80, 0.99] (default 0.92)" },
        ttl: { type: "integer", description: "Cache TTL in seconds (default 86400)" },
        model: { type: "string", description: "LLM model slug for the gateway" },
      },
      required: ["engagement_id", "prompt"],
    },
  },
  {
    name: "cache_stats",
    description: "Get semantic cache hit/miss stats and severity rollup for an engagement.",
    inputSchema: {
      type: "object",
      properties: {
        engagement_id: { type: "string" },
      },
      required: ["engagement_id"],
    },
  },
  {
    name: "engagement_report",
    description: "Full engagement export: all findings (paginated), severity+status rollups, recent memories, cache stats. Use for SOC report generation or cross-tool analysis.",
    inputSchema: {
      type: "object",
      properties: {
        engagement_id: { type: "string" },
        cursor: { type: "string", description: "Pagination cursor from a previous call's next_cursor" },
        limit: { type: "integer", description: "Findings per page (default 200, max 500)" },
      },
      required: ["engagement_id"],
    },
  },
];

/**
 * Read the request body with a 64KB size guard.
 * Returns parsed body or a JSON-RPC error Response.
 */
async function readBody(c: Context<AppContext>): Promise<{ body: Record<string, unknown> } | { error: Response }> {
  try {
    const reader = c.req.raw.body?.getReader();
    if (!reader) {
      return { error: Response.json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Empty body" } }, { status: 400 }) };
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > 65536) {
        return {
          error: Response.json(
            { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Request body too large" } },
            { status: 413 }
          ),
        };
      }
      chunks.push(value);
    }
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.length;
    }
    const body = JSON.parse(new TextDecoder().decode(merged)) as Record<string, unknown>;
    return { body };
  } catch {
    return {
      error: Response.json(
        { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } },
        { status: 400 }
      ),
    };
  }
}

/**
 * Dispatch a tools/call invocation to the corresponding handler.
 * Returns the handler's Response and unwraps it to JSON for MCP wrapping.
 */
async function dispatchTool(
  name: string,
  args: Record<string, unknown>,
  env: Env,
  c: Context<AppContext>
): Promise<unknown> {
  switch (name) {
    case "engagement_open":
      return extractJson(await handleEngagementOpen(args, env));

    case "engagement_list": {
      // #3: engagement_list MCP tool
      const status = typeof args["status"] === "string" ? args["status"] : null;
      let stmt: D1PreparedStatement;
      if (status) {
        stmt = env.DB.prepare(
          `SELECT engagement_id, name, client, status, created_at
           FROM engagements
           WHERE deleted_at IS NULL AND status = ?
           ORDER BY created_at DESC LIMIT 100`
        ).bind(status);
      } else {
        stmt = env.DB.prepare(
          `SELECT engagement_id, name, client, status, created_at
           FROM engagements
           WHERE deleted_at IS NULL
           ORDER BY created_at DESC LIMIT 100`
        );
      }
      const { results } = await stmt.all<Pick<EngagementRecord, "engagement_id" | "name" | "client" | "status" | "created_at">>();
      return { engagements: results ?? [] };
    }

    case "sec_cache_get": {
      const ns = String(args["ns"] ?? "");
      const key = String(args["key"] ?? "");
      return extractJson(await handleKvGet(ns, key, env));
    }

    case "sec_cache_set": {
      const ns = String(args["ns"] ?? "");
      const key = String(args["key"] ?? "");
      return extractJson(await handleKvSet(ns, key, args, env, c));
    }

    case "finding_store":
      return extractJson(await handleFindingStore(args, env));

    case "finding_batch":
      return extractJson(await handleFindingBatch(args, env));

    case "finding_search":
      return extractJson(await handleFindingSearch(args, env));

    case "engagement_remember":
      return extractJson(await handleRemember(args, env));

    case "engagement_recall": {
      // #4: pass query through — if present, vector_recall is implied
      const recallArgs = { ...args };
      if (typeof recallArgs["query"] === "string" && recallArgs["query"].length > 0) {
        recallArgs["vector_recall"] = true;
      }
      return extractJson(await handleRecall(recallArgs, env));
    }

    case "semantic_triage":
      return extractJson(await handleSemanticTriage(args, env));

    case "cache_stats": {
      const eid = typeof args["engagement_id"] === "string" ? args["engagement_id"] : null;
      return extractJson(await handleCacheStats(eid, env));
    }

    case "engagement_report": {
      const eid = String(args["engagement_id"] ?? "");
      const cur = typeof args["cursor"] === "string" ? args["cursor"] : null;
      const lim = typeof args["limit"] === "number" ? args["limit"] : null;
      return extractJson(await handleEngagementReport(eid, env, cur, lim));
    }

    default: {
      const err = new Error(`Unknown tool: ${name}`) as Error & { status: number };
      err.status = 400;
      throw err;
    }
  }
}

/** Extract JSON from a Response object. */
async function extractJson(resp: Response): Promise<unknown> {
  const text = await resp.text();
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/**
 * MCP JSON-RPC POST handler.
 * Mounted at POST /mcp (behind verifyAuth in src/index.ts).
 */
export async function handleMcp(c: Context<AppContext>): Promise<Response> {
  const parsed = await readBody(c);
  if ("error" in parsed) return parsed.error;

  const { body } = parsed;
  const method = body["method"] as string | undefined;
  const id = body["id"] as string | number | null | undefined;
  const params = (body["params"] ?? {}) as Record<string, unknown>;

  try {
    // MCP handshake
    if (method === "initialize") {
      return Response.json({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "siemen", version: "0.1.0" },
        },
      });
    }

    // Client ack — no response body needed
    if (method === "notifications/initialized") {
      return new Response(null, { status: 204 });
    }

    // Keepalive
    if (method === "ping") {
      return Response.json({ jsonrpc: "2.0", id, result: {} });
    }

    // Tool manifest
    if (method === "tools/list") {
      return Response.json({
        jsonrpc: "2.0",
        id,
        result: { tools: TOOL_MANIFEST },
      });
    }

    // Tool dispatch
    if (method === "tools/call") {
      const toolName = params["name"] as string | undefined;
      const toolArgs = (params["arguments"] ?? {}) as Record<string, unknown>;

      if (!toolName) {
        return Response.json(
          { jsonrpc: "2.0", id, error: { code: -32602, message: "params.name required" } },
          { status: 400 }
        );
      }

      const result = await dispatchTool(toolName, toolArgs, c.env, c);
      return Response.json({
        jsonrpc: "2.0",
        id,
        result: { content: [{ type: "text", text: JSON.stringify(result) }] },
      });
    }

    // Method not found — do not reflect method name back (P3-2 security pattern)
    return Response.json(
      { jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } },
      { status: 404 }
    );
  } catch (err) {
    const e = err as Error & { status?: number };
    const httpStatus = [400, 404, 429].includes(e.status ?? 0) ? (e.status ?? 500) : 500;
    if (httpStatus === 500) {
      console.error("[siemen/mcp] internal error:", e.message, e.stack);
    }
    const userMessage =
      httpStatus === 400 ? e.message :
      httpStatus === 404 ? "Not found" :
      httpStatus === 429 ? "Rate limit exceeded" :
      "Internal server error";
    return Response.json(
      { jsonrpc: "2.0", id, error: { code: httpStatus === 500 ? -32603 : -32602, message: userMessage } },
      { status: httpStatus }
    );
  }
}
