// REST routes for fast K/V scratch store.
// Delegates to handlers/kv.ts (shared with MCP tools/call).

import { Hono } from "hono";
import type { Env, Variables } from "../types.js";
import { handleKvGet, handleKvSet } from "../handlers/kv.js";

const kvRoutes = new Hono<{ Bindings: Env; Variables: Variables }>();

// GET /v1/kv/:ns/:key — read scratch value
kvRoutes.get("/v1/kv/:ns/:key", async (c) => {
  const ns = c.req.param("ns");
  const key = c.req.param("key");
  return handleKvGet(ns, key, c.env);
});

// POST /v1/kv/:ns/:key — write scratch value (legacy method)
kvRoutes.post("/v1/kv/:ns/:key", async (c) => {
  const ns = c.req.param("ns");
  const key = c.req.param("key");
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "VALIDATION_ERROR", message: "Invalid JSON body" }, 400);
  }
  return handleKvSet(ns, key, body, c.env, c);
});

// PUT /v1/kv/:ns/:key — write scratch value (spec-correct method)
kvRoutes.put("/v1/kv/:ns/:key", async (c) => {
  const ns = c.req.param("ns");
  const key = c.req.param("key");
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "VALIDATION_ERROR", message: "Invalid JSON body" }, 400);
  }
  return handleKvSet(ns, key, body, c.env, c);
});

export { kvRoutes };
