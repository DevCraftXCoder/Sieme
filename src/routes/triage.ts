// REST routes for semantic-cache-backed LLM triage.
// Delegates to cache.ts handleSemanticTriage (shared with MCP tools/call).
// #10: POST /v1/triage/warm  — cache pre-seeding
// #13: GET  /v1/triage/history — semantic_cache_log query

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

// POST /v1/triage/warm — cache pre-seeding (#10)
triageRoutes.post("/v1/triage/warm", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "VALIDATION_ERROR", message: "Invalid JSON body" }, 400);
  }

  if (!body || typeof body !== "object") {
    return c.json({ error: "VALIDATION_ERROR", message: "Body required" }, 400);
  }
  const b = body as Record<string, unknown>;

  if (!b["engagement_id"] || typeof b["engagement_id"] !== "string") {
    return c.json({ error: "VALIDATION_ERROR", message: "engagement_id required" }, 400);
  }
  if (!Array.isArray(b["prompts"])) {
    return c.json({ error: "VALIDATION_ERROR", message: "prompts array required" }, 400);
  }

  const prompts = b["prompts"] as unknown[];
  if (prompts.length > 20) {
    return c.json({ error: "VALIDATION_ERROR", message: "Max 20 prompts per warm call" }, 400);
  }

  const engagementId = b["engagement_id"] as string;
  let warmed = 0;
  let already_cached = 0;

  for (const p of prompts) {
    if (typeof p !== "string" || p.length === 0) continue;
    try {
      const resp = await handleSemanticTriage(
        { engagement_id: engagementId, prompt: p },
        c.env
      );
      if (resp.status === 200) {
        const data = await resp.json() as { outcome?: string };
        if (data.outcome === "exact_hit" || data.outcome === "semantic_hit") {
          already_cached++;
        } else {
          warmed++;
        }
      }
    } catch {
      // Non-fatal — continue warming other prompts
    }
  }

  return c.json({ warmed, already_cached });
});

// GET /v1/triage/history?engagement_id=UUID — cache log query (#13)
triageRoutes.get("/v1/triage/history", async (c) => {
  const engagementId = c.req.query("engagement_id") ?? null;
  if (!engagementId) {
    return c.json({ error: "VALIDATION_ERROR", message: "engagement_id query param required" }, 400);
  }

  const limitParam = c.req.query("limit");
  const limit = limitParam ? Math.min(Math.max(parseInt(limitParam, 10) || 20, 1), 100) : 20;

  const { results } = await c.env.DB.prepare(
    `SELECT id, prompt_hash, outcome, similarity, model, created_at
     FROM semantic_cache_log
     WHERE engagement_id = ?
     ORDER BY created_at DESC
     LIMIT ?`
  )
    .bind(engagementId, limit)
    .all<{
      id: string;
      prompt_hash: string;
      outcome: string;
      similarity: number | null;
      model: string | null;
      created_at: string;
    }>();

  return c.json({ history: results ?? [], engagement_id: engagementId });
});

export { triageRoutes };
