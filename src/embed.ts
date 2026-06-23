// Embedding provider cascade:
// 1. Workers AI (primary in production — no external call, 768-dim BGE)
// 2. OpenRouter (dev/host path — skip if key absent)
// 3. Ollama (dev/offline — skip if running on CF edge, unreachable from there)
//
// Input capped at 2000 chars before any provider call (BGE token limit guard).
// All three providers must emit 768-dim vectors (index frozen at create time).

import type { Env } from "./types.js";

/** Max input length before embed — BGE-base-en-v1.5 has ~512 token limit. */
const MAX_EMBED_CHARS = 2000;

/**
 * Validate text length before embedding.
 * Throws a 400-status error when the input exceeds MAX_EMBED_CHARS.
 */
export function validateEmbedInput(text: string, fieldName = "content"): void {
  if (typeof text !== "string") {
    const err = new Error(`${fieldName} must be a string`) as Error & { status: number };
    err.status = 400;
    throw err;
  }
  if (text.length > MAX_EMBED_CHARS) {
    const err = new Error(
      `${fieldName} exceeds the ${MAX_EMBED_CHARS} character limit (got ${text.length})`
    ) as Error & { status: number };
    err.status = 400;
    throw err;
  }
}

/**
 * Sanitize and validate a tags array.
 * Max 10 tags, max 50 chars each, strips non-printable characters.
 */
export function validateAndSanitizeTags(tags: unknown): string[] {
  if (!Array.isArray(tags)) {
    const err = new Error("tags must be an array") as Error & { status: number };
    err.status = 400;
    throw err;
  }
  if (tags.length > 10) {
    const err = new Error("tags array exceeds the limit of 10 tags") as Error & { status: number };
    err.status = 400;
    throw err;
  }
  return tags.map((tag: unknown, i: number) => {
    if (typeof tag !== "string") {
      const err = new Error(`tags[${i}] must be a string`) as Error & { status: number };
      err.status = 400;
      throw err;
    }
    // Strip non-printable characters (keep printable ASCII + common Unicode)
    const sanitized = tag.replace(/[^\x20-\x7E -￿]/g, "").trim();
    if (sanitized.length === 0) {
      const err = new Error(`tags[${i}] is empty after sanitization`) as Error & { status: number };
      err.status = 400;
      throw err;
    }
    if (sanitized.length > 50) {
      const err = new Error(
        `tags[${i}] exceeds the 50 character limit (got ${sanitized.length})`
      ) as Error & { status: number };
      err.status = 400;
      throw err;
    }
    return sanitized;
  });
}

/**
 * Embed text via the provider cascade.
 * Returns a 768-dim float array.
 *
 * Cascade order (production-safe path first):
 * 1. Workers AI — @cf/baai/bge-base-en-v1.5 (768-dim, no external call)
 * 2. OpenRouter — skip if OPENROUTER_API_KEY absent
 * 3. Ollama — skip if running on CF edge (localhost unreachable)
 *
 * Throws 503 if all three rungs fail.
 */
export async function embed(text: string, env: Env): Promise<number[]> {
  // Rung 1: Workers AI (production primary)
  try {
    const result = await env.AI.run("@cf/baai/bge-base-en-v1.5", {
      text: [text],
    }) as { data: number[][] };
    return result.data[0];
  } catch (e) {
    console.warn("[siemen/embed] Workers AI failed, trying OpenRouter:", (e as Error).message);
  }

  // Rung 2: OpenRouter (dev/host path)
  if (env.OPENROUTER_API_KEY) {
    try {
      const resp = await fetch(env.OPENROUTER_EMBED_URL, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.OPENROUTER_API_KEY}`,
          "Content-Type": "application/json",
          "HTTP-Referer": env.HTTP_REFERER,
          "X-Title": env.X_TITLE,
        },
        body: JSON.stringify({
          model: "text-embedding-ada-002",
          input: text,
        }),
      });
      if (resp.ok) {
        const data = await resp.json() as { data: Array<{ embedding: number[] }> };
        return data.data[0].embedding;
      }
      console.warn("[siemen/embed] OpenRouter returned", resp.status, "- trying Ollama");
    } catch (e) {
      console.warn("[siemen/embed] OpenRouter failed, trying Ollama:", (e as Error).message);
    }
  }

  // Rung 3: Ollama (dev/offline — localhost unreachable from CF edge)
  // Only attempt if the URL doesn't point to localhost on a deployed worker.
  const ollamaUrl = env.OLLAMA_EMBED_URL;
  if (ollamaUrl && !ollamaUrl.includes("localhost") && !ollamaUrl.includes("127.0.0.1")) {
    try {
      const resp = await fetch(ollamaUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: "nomic-embed-text", prompt: text }),
      });
      if (resp.ok) {
        const data = await resp.json() as { embedding: number[] };
        return data.embedding;
      }
    } catch (e) {
      console.warn("[siemen/embed] Ollama failed:", (e as Error).message);
    }
  } else if (ollamaUrl) {
    // Localhost Ollama — only reachable in wrangler dev on host, not from CF edge.
    // Log warning during dev; silently skip on edge.
    console.warn("[siemen/embed] Ollama at localhost skipped (unreachable from CF edge)");
  }

  // All three rungs failed
  const err = new Error("Embedding service unavailable") as Error & { status: number };
  err.status = 503;
  throw err;
}
