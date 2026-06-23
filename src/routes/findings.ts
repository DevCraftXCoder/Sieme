// REST routes for findings, engagements, and cache stats.
// Delegates to handlers/findings.ts (shared with MCP tools/call).

import { Hono } from "hono";
import type { Env, Variables } from "../types.js";
import {
  handleEngagementOpen,
  handleFindingStore,
  handleFindingSearch,
  handleCacheStats,
} from "../handlers/findings.js";

const findingsRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

// POST /v1/engagements — create/register an engagement
findingsRoutes.post("/v1/engagements", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "VALIDATION_ERROR", message: "Invalid JSON body" }, 400);
  }
  return handleEngagementOpen(body, c.env);
});

// POST /v1/findings — embed + store a finding/CVE/control
findingsRoutes.post("/v1/findings", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "VALIDATION_ERROR", message: "Invalid JSON body" }, 400);
  }
  return handleFindingStore(body, c.env);
});

// POST /v1/findings/search — semantic RAG over findings
findingsRoutes.post("/v1/findings/search", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "VALIDATION_ERROR", message: "Invalid JSON body" }, 400);
  }
  return handleFindingSearch(body, c.env);
});

// GET /v1/stats — cache hit/miss stats for an engagement
findingsRoutes.get("/v1/stats", async (c) => {
  const engagementId = c.req.query("engagement_id") ?? null;
  return handleCacheStats(engagementId, c.env);
});

export { findingsRoutes };
