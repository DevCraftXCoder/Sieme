// SIEMen — Security AI Data Layer (edge-native CF Worker)
// Hono app entry: mounts all routes and MCP surface.
//
// Auth model:
//   GET /health — unauthed, always 200
//   POST /mcp   — Bearer authed (verifyAuth middleware)
//   /v1/*       — Bearer authed (verifyAuth middleware)

import { Hono } from "hono";
import type { Env, Variables } from "./types.js";
import { verifyAuth } from "./auth.js";
import { kvRoutes } from "./routes/kv.js";
import { findingsRoutes } from "./routes/findings.js";
import { memoryRoutes } from "./routes/memory.js";
import { triageRoutes } from "./routes/triage.js";
import { handleMcp } from "./mcp.js";

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// ── Health check (unauthed) ───────────────────────────────────────────────────
app.get("/health", (c) => {
  return c.json({ status: "ok", service: "siemen", version: "0.1.0", ts: Date.now() });
});

// ── Auth middleware for all protected routes ───────────────────────────────────
// Applied per-route group so /health remains unauthed.
app.use("/v1/*", verifyAuth);
app.use("/mcp", verifyAuth);

// ── REST route groups ─────────────────────────────────────────────────────────
app.route("/", kvRoutes);
app.route("/", findingsRoutes);
app.route("/", memoryRoutes);
app.route("/", triageRoutes);

// ── MCP JSON-RPC surface ──────────────────────────────────────────────────────
app.post("/mcp", handleMcp);

// ── Catch-all error handlers ──────────────────────────────────────────────────
app.notFound((c) => {
  return c.json({ error: "NOT_FOUND", message: "Route not found" }, 404);
});

app.onError((err, c) => {
  const e = err as Error & { status?: number };
  console.error("[siemen] unhandled error:", e.message, e.stack);
  return c.json(
    { error: "INTERNAL_ERROR", message: "An unexpected error occurred" },
    (e.status as 400 | 500) ?? 500
  );
});

export default app;
