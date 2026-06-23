// KV scratch store handlers: sec_cache_get / sec_cache_set
// Key format: kv:<ns>:<key> — avoids collision with mem:*, exact:*, an:* prefixes.
// Used by both REST routes (src/routes/kv.ts) and MCP tools/call dispatcher (src/mcp.ts).

import type { Context } from "hono";
import type { Env, Variables } from "../types.js";

type AppContext = { Bindings: Env; Variables: Variables };

/** Max TTL for KV scratch writes (24h). */
const MAX_TTL_SECONDS = 86400;

/** Strip colons from namespace and key to prevent prefix pollution. */
function sanitizeSegment(s: string): string {
  return s.replace(/:/g, "_").slice(0, 128);
}

/**
 * Read a value from the fast KV scratch store.
 * GET /v1/kv/:ns/:key
 */
export async function handleKvGet(
  ns: string,
  key: string,
  env: Env
): Promise<Response> {
  const safeNs = sanitizeSegment(ns);
  const safeKey = sanitizeSegment(key);
  const kvKey = `kv:${safeNs}:${safeKey}`;

  const value = await env.KV.get(kvKey);
  if (value === null) {
    return Response.json({ error: "NOT_FOUND", message: "Key not found" }, { status: 404 });
  }
  return Response.json({ value });
}

/**
 * Write a value to the fast KV scratch store.
 * POST /v1/kv/:ns/:key
 *
 * Body: { value: string; ttl?: number }
 * Rate-limited via SIEMEN_RATE_LIMITER binding.
 */
export async function handleKvSet(
  ns: string,
  key: string,
  body: unknown,
  env: Env,
  c: Context<AppContext>
): Promise<Response> {
  // Rate limit check
  const rl = await env.SIEMEN_RATE_LIMITER.limit({ key: c.get("callerHash") });
  if (!rl.success) {
    return Response.json(
      { error: "RATE_LIMIT_EXCEEDED", message: "Too many requests" },
      { status: 429 }
    );
  }

  if (!body || typeof body !== "object") {
    return Response.json({ error: "VALIDATION_ERROR", message: "Request body required" }, { status: 400 });
  }

  const b = body as Record<string, unknown>;

  if (typeof b["value"] !== "string") {
    return Response.json({ error: "VALIDATION_ERROR", message: "value must be a string" }, { status: 400 });
  }

  const value = b["value"];
  let ttl: number | undefined;

  if (b["ttl"] !== undefined) {
    ttl = Number(b["ttl"]);
    if (!Number.isFinite(ttl) || ttl < 1 || ttl > MAX_TTL_SECONDS) {
      return Response.json(
        { error: "VALIDATION_ERROR", message: `ttl must be between 1 and ${MAX_TTL_SECONDS}` },
        { status: 400 }
      );
    }
  }

  const safeNs = sanitizeSegment(ns);
  const safeKey = sanitizeSegment(key);
  const kvKey = `kv:${safeNs}:${safeKey}`;

  const putOptions: KVNamespacePutOptions = ttl !== undefined ? { expirationTtl: ttl } : {};
  await env.KV.put(kvKey, value, putOptions);

  return Response.json({ ok: true, key: kvKey }, { status: 201 });
}
