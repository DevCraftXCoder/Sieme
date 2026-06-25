// REST routes for findings, engagements, and cache stats.
// Delegates to handlers/findings.ts (shared with MCP tools/call).

import { Hono } from "hono";
import type { Env, Variables } from "../types.js";
import type { EngagementRecord } from "../types.js";
import {
  handleEngagementOpen,
  handleEngagementUpdate,
  handleEngagementReport,
  handleFindingStore,
  handleFindingBatch,
  handleFindingSearch,
  handleFindingUpdate,
  handleFindingDelete,
  handleCacheStats,
} from "../handlers/findings.js";

const findingsRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

// GET /v1/engagements — list all engagements (non-deleted, newest first)
findingsRoutes.get("/v1/engagements", async (c) => {
  const status = c.req.query("status") ?? null;
  let stmt: D1PreparedStatement;
  if (status) {
    stmt = c.env.DB.prepare(
      `SELECT engagement_id, name, client, status, created_at, updated_at
       FROM engagements
       WHERE deleted_at IS NULL AND status = ?
       ORDER BY created_at DESC LIMIT 100`
    ).bind(status);
  } else {
    stmt = c.env.DB.prepare(
      `SELECT engagement_id, name, client, status, created_at, updated_at
       FROM engagements
       WHERE deleted_at IS NULL
       ORDER BY created_at DESC LIMIT 100`
    );
  }
  const { results } = await stmt.all<Pick<EngagementRecord, "engagement_id" | "name" | "client" | "status" | "created_at" | "updated_at">>();
  return c.json({ engagements: results ?? [] });
});

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

// GET /v1/engagements/:id/report — full engagement export (Gap 3: SIC→SOC pipeline)
// Returns all findings (paginated), severity+status rollups, memories, cache stats.
// Query params: ?cursor=<base64>&limit=<n>
findingsRoutes.get("/v1/engagements/:id/report", async (c) => {
  const engagementId = c.req.param("id");
  const cursor = c.req.query("cursor") ?? null;
  const limitRaw = c.req.query("limit");
  const limit = limitRaw ? parseInt(limitRaw, 10) : null;
  return handleEngagementReport(engagementId, c.env, cursor, limit);
});

// PATCH /v1/engagements/:id — update status/name/client (#7)
findingsRoutes.patch("/v1/engagements/:id", async (c) => {
  const engagementId = c.req.param("id");
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "VALIDATION_ERROR", message: "Invalid JSON body" }, 400);
  }
  return handleEngagementUpdate(engagementId, body, c.env);
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

// POST /v1/findings/batch — batch ingest (#1)
findingsRoutes.post("/v1/findings/batch", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "VALIDATION_ERROR", message: "Invalid JSON body" }, 400);
  }
  return handleFindingBatch(body, c.env);
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

// PATCH /v1/findings/:id — update severity/body/tags (#5)
findingsRoutes.patch("/v1/findings/:id", async (c) => {
  const recordId = c.req.param("id");
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "VALIDATION_ERROR", message: "Invalid JSON body" }, 400);
  }
  return handleFindingUpdate(recordId, body, c.env);
});

// DELETE /v1/findings/:id — soft delete (#9)
findingsRoutes.delete("/v1/findings/:id", async (c) => {
  const recordId = c.req.param("id");
  return handleFindingDelete(recordId, c.env);
});

// GET /v1/stats — cache hit/miss stats + severity rollup for an engagement (#2)
findingsRoutes.get("/v1/stats", async (c) => {
  const engagementId = c.req.query("engagement_id") ?? null;
  return handleCacheStats(engagementId, c.env);
});

export { findingsRoutes };
