// Semantic cache for LLM security analyses (semantic_triage).
// Exact short-circuit (SHA-256 hash lookup in KV) → semantic similarity (Vectorize) → LLM miss.
// See spec §7 for the full hit/miss flow.
//
// Key namespacing:
//   "exact:<prompt_hash>" — exact-match short-circuit in SC_KV
//   "an:<uuid>"           — analysis payload key in SC_KV
//
// Does NOT import from packages/llm-gateway — LLM call is a plain fetch to env.LLM_GATEWAY_URL.

import { embed, validateEmbedInput } from "./embed.js";
import type { Env, SemanticCacheLogRow } from "./types.js";

/** Skip caching responses whose serialised length exceeds this (8KB). */
const MAX_CACHE_CHARS = 8000;

/** Default cosine similarity threshold for a semantic hit. */
const DEFAULT_THRESHOLD = 0.92;

/** Threshold bounds — clamp to [0.80, 0.99] per spec §7. */
const THRESHOLD_MIN = 0.80;
const THRESHOLD_MAX = 0.99;

/** Default semantic cache TTL in seconds (24h). */
const DEFAULT_TTL_SECONDS = 86400;

// ── SHA-256 helper (Web Crypto — no Node.js crypto) ──────────────────────────

async function sha256Hex(text: string): Promise<string> {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── Cache log (non-fatal, best-effort) ───────────────────────────────────────

async function logCacheEvent(
  env: Env,
  row: Partial<SemanticCacheLogRow>
): Promise<void> {
  try {
    const id = crypto.randomUUID();
    const ts = new Date().toISOString();
    await env.DB.prepare(
      `INSERT INTO semantic_cache_log
         (id, engagement_id, prompt_hash, outcome, similarity, cache_key, model, tokens_saved, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        id,
        row.engagement_id ?? null,
        row.prompt_hash ?? "",
        row.outcome ?? "miss",
        row.similarity ?? null,
        row.cache_key ?? null,
        row.model ?? null,
        row.tokens_saved ?? null,
        ts
      )
      .run();
  } catch {
    // Non-fatal — swallow so a logging failure never breaks the triage path
  }
}

// ── semantic_triage body type ─────────────────────────────────────────────────

export interface SemanticTriageBody {
  engagement_id: string;
  prompt: string;
  threshold?: number;
  ttl?: number;
  model?: string;
}

// ── handleSemanticTriage ──────────────────────────────────────────────────────

/**
 * Semantic-cache-backed LLM triage per spec §7.
 *
 * Flow:
 * 1. Normalize prompt → SHA-256 hash.
 * 2. Exact short-circuit: SC_KV.get("exact:" + hash).
 * 3. Embed prompt → Vectorize.query(namespace=engagement_id, kind=analysis, topK=3).
 * 4. Hit if best score >= threshold → return cached payload.
 * 5. Miss → call LLM via llm-gateway → cache result → upsert analysis vector → return.
 */
export async function handleSemanticTriage(body: unknown, env: Env): Promise<Response> {
  if (!body || typeof body !== "object") {
    return Response.json({ error: "VALIDATION_ERROR", message: "Body required" }, { status: 400 });
  }
  const b = body as Record<string, unknown>;

  if (!b["engagement_id"] || typeof b["engagement_id"] !== "string") {
    return Response.json({ error: "VALIDATION_ERROR", message: "engagement_id required" }, { status: 400 });
  }
  if (!b["prompt"] || typeof b["prompt"] !== "string") {
    return Response.json({ error: "VALIDATION_ERROR", message: "prompt required" }, { status: 400 });
  }

  const engagementId = b["engagement_id"] as string;
  const rawPrompt = b["prompt"] as string;
  const model = typeof b["model"] === "string" ? b["model"] : "anthropic/claude-haiku-4.5";
  const ttl = typeof b["ttl"] === "number" && b["ttl"] > 0 ? Math.min(b["ttl"], DEFAULT_TTL_SECONDS * 7) : DEFAULT_TTL_SECONDS;

  // Clamp threshold to [0.80, 0.99]
  const rawThreshold = typeof b["threshold"] === "number" ? b["threshold"] : DEFAULT_THRESHOLD;
  const threshold = Math.max(THRESHOLD_MIN, Math.min(THRESHOLD_MAX, rawThreshold));

  // Step 1: Normalize for hashing (trim + collapse whitespace + lowercase)
  const normalized = rawPrompt.trim().replace(/\s+/g, " ").toLowerCase();
  const promptHash = await sha256Hex(normalized + engagementId);

  // Step 2: Exact short-circuit
  const exactKey = `exact:${promptHash}`;
  const exactHit = await env.SC_KV.get(exactKey);
  if (exactHit !== null) {
    await logCacheEvent(env, {
      engagement_id: engagementId,
      prompt_hash: promptHash,
      outcome: "exact_hit",
      cache_key: exactKey,
      model,
    });
    return Response.json({
      outcome: "exact_hit",
      analysis: exactHit,
      cached: true,
    });
  }

  // Step 3: Embed prompt (validate input first)
  validateEmbedInput(rawPrompt, "prompt");
  const vector = await embed(rawPrompt, env);

  // Step 4: Vectorize similarity query
  const matches = await env.VECTORIZE.query(vector, {
    topK: 3,
    returnMetadata: "indexed",
    namespace: engagementId,
    filter: { kind: "analysis" },
  });

  const bestMatch = (matches.matches ?? [])[0];
  if (bestMatch && bestMatch.score >= threshold) {
    const matchMeta = bestMatch.metadata as Record<string, unknown> | undefined;
    const cacheKey = typeof matchMeta?.["cache_key"] === "string" ? matchMeta["cache_key"] : null;

    if (cacheKey) {
      const payload = await env.SC_KV.get(cacheKey);
      if (payload !== null) {
        // Semantic hit
        await logCacheEvent(env, {
          engagement_id: engagementId,
          prompt_hash: promptHash,
          outcome: "semantic_hit",
          similarity: bestMatch.score,
          cache_key: cacheKey,
          model,
        });
        return Response.json({
          outcome: "semantic_hit",
          analysis: payload,
          cached: true,
          similarity: bestMatch.score,
        });
      }
      // Payload expired — fall through to miss
    }
  }

  // Step 5: MISS — call LLM via llm-gateway
  let analysis: string;
  try {
    const llmResp = await fetch(env.LLM_GATEWAY_URL, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.LLM_GATEWAY_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        messages: [
          {
            role: "system",
            content: "You are a security analyst. Triage the following finding concisely.",
          },
          { role: "user", content: rawPrompt },
        ],
        max_tokens: 512,
      }),
    });

    if (!llmResp.ok) {
      const errText = await llmResp.text();
      return Response.json(
        { error: "LLM_ERROR", message: `LLM gateway returned ${llmResp.status}`, details: errText },
        { status: 502 }
      );
    }

    const llmData = await llmResp.json() as {
      choices: Array<{ message: { content: string } }>;
    };
    analysis = llmData.choices?.[0]?.message?.content ?? "";
  } catch (e) {
    return Response.json(
      { error: "LLM_ERROR", message: "LLM gateway call failed", details: (e as Error).message },
      { status: 502 }
    );
  }

  // Cache the result (only if within size limit)
  const uuid = crypto.randomUUID();
  const cacheKey = `an:${uuid}`;

  if (analysis.length <= MAX_CACHE_CHARS) {
    // Write to KV (exact + cache_key)
    const kvOpts = { expirationTtl: ttl };
    await Promise.all([
      env.SC_KV.put(cacheKey, analysis, kvOpts),
      env.SC_KV.put(exactKey, analysis, kvOpts),
    ]);

    // Upsert analysis vector (embed already computed above)
    await env.VECTORIZE.upsert([
      {
        id: `analysis:${uuid}`,
        values: vector,
        namespace: engagementId,
        metadata: { kind: "analysis", engagement_id: engagementId, cache_key: cacheKey },
      },
    ]);
  }

  await logCacheEvent(env, {
    engagement_id: engagementId,
    prompt_hash: promptHash,
    outcome: "miss",
    cache_key: cacheKey,
    model,
  });

  return Response.json({
    outcome: "miss",
    analysis,
    cached: false,
  });
}
