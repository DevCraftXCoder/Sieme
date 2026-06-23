// REST routes for per-engagement agent memory.
// Delegates to handlers/memory.ts (shared with MCP tools/call).

import { Hono } from "hono";
import type { Env, Variables } from "../types.js";
import { handleRemember, handleRecall } from "../handlers/memory.js";

const memoryRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

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
