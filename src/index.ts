// SIEMen — Security AI Data Layer (edge-native CF Worker)
// Hono app entry: mounts all routes and MCP surface.
//
// Auth model:
//   GET /health — unauthed, always 200 (degraded if checks fail)
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

// ── Health check (unauthed) — expanded with subsystem checks (#11) ────────────
app.get("/health", async (c) => {
  const checks: Record<string, "ok" | "error"> = {
    d1: "ok",
    kv: "ok",
    vectorize: "ok",
  };

  // Run checks in parallel — errors are caught individually
  await Promise.all([
    // D1 check
    c.env.DB.prepare("SELECT 1").first().then(
      () => { checks["d1"] = "ok"; },
      () => { checks["d1"] = "error"; }
    ),
    // KV check (read a sentinel key — absence is fine, errors are not)
    c.env.SC_KV.get("__health__").then(
      () => { checks["kv"] = "ok"; },
      () => { checks["kv"] = "error"; }
    ),
    // Vectorize check — dummy query with zero vector (768-dim)
    c.env.VECTORIZE.query(new Array(768).fill(0) as number[], { topK: 1 }).then(
      () => { checks["vectorize"] = "ok"; },
      () => { checks["vectorize"] = "error"; }
    ),
  ]);

  const degraded = Object.values(checks).some((v) => v === "error");

  return c.json({
    status: degraded ? "degraded" : "ok",
    service: "siemen",
    version: "0.1.0",
    ts: Date.now(),
    checks,
  });
  // Always 200 — callers check top-level status field
});

// ── Auth middleware for all protected routes ───────────────────────────────────
// Applied per-route group so /health remains unauthed.
app.use("/v1/*", verifyAuth);
app.use("/mcp", verifyAuth);

// ── Rate limit middleware on /v1/* — adds Retry-After + X-RateLimit-Limit headers (#6) ──
app.use("/v1/*", async (c, next) => {
  const callerHash = c.get("callerHash");
  if (!callerHash) return next(); // verifyAuth already rejected if missing

  const rl = await c.env.SIEMEN_RATE_LIMITER.limit({ key: callerHash });
  if (!rl.success) {
    return c.json(
      { error: "RATE_LIMIT_EXCEEDED", message: "Too many requests" },
      429,
      {
        "Retry-After": "60",
        "X-RateLimit-Limit": "60",
      }
    );
  }

  return next();
});

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
