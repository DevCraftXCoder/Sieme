// REST routes for per-engagement agent memory.
// Delegates to handlers/memory.ts (shared with MCP tools/call).
// GET /v1/memory supports:
//   - ?engagement_id=UUID             → recency recall (existing)
//   - ?engagement_id=UUID&query=text  → vector similarity recall (#4)
//   - ?query=text                     → cross-engagement similarity search (#15)

import { Hono } from "hono";
import type { Env, Variables } from "../types.js";
import { handleRemember, handleRecall, handleCrossEngagementRecall } from "../handlers/memory.js";

const memoryRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

// GET /v1/memory — recall memories (recency, vector, or cross-engagement)
memoryRoutes.get("/v1/memory", async (c) => {
  const engagementId = c.req.query("engagement_id") ?? null;
  const query = c.req.query("query") ?? null;
  const topKParam = c.req.query("top_k");
  const topK = topKParam ? Math.min(parseInt(topKParam, 10) || 10, 50) : 10;
  const sessionId = c.req.query("session_id") ?? null;

  // #15: Cross-engagement search — no engagement_id but query is present
  if (!engagementId && query) {
    return handleCrossEngagementRecall(query, topK, c.env);
  }

  if (!engagementId) {
    return c.json(
      { error: "VALIDATION_ERROR", message: "engagement_id or query (for cross-engagement search) is required" },
      400
    );
  }

  // #4: Vector similarity if query param provided, else recency
  const vectorRecall = query !== null;
  const body = {
    engagement_id: engagementId,
    top_k: topK,
    ...(sessionId ? { session_id: sessionId } : {}),
    ...(vectorRecall ? { query, vector_recall: true } : { vector_recall: false }),
  };
  return handleRecall(body, c.env);
});

// POST /v1/memory — store agent memory
memoryRoutes.post("/v1/memory", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "VALIDATION_ERROR", message: "Invalid JSON body" }, 400);
  }
  return handleRemember(body, c.env);
});

// POST /v1/memory/search — recall memory by engagement (vector or recency)
memoryRoutes.post("/v1/memory/search", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "VALIDATION_ERROR", message: "Invalid JSON body" }, 400);
  }
  return handleRecall(body, c.env);
});

export { memoryRoutes };
