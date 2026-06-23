// REST route for semantic-cache-backed LLM triage.
// Delegates to cache.ts handleSemanticTriage (shared with MCP tools/call).

import { Hono } from "hono";
import type { Env, Variables } from "../types.js";
import { handleSemanticTriage } from "../cache.js";

const triageRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

// POST /v1/triage — semantic triage with cache
triageRoutes.post("/v1/triage", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "VALIDATION_ERROR", message: "Invalid JSON body" }, 400);
  }
  return handleSemanticTriage(body, c.env);
});

export { triageRoutes };
