// Memory handlers: engagement_remember, engagement_recall
// Used by both REST routes (src/routes/memory.ts) and MCP tools/call (src/mcp.ts).
// deleteByIds discipline: Vectorize delete must succeed before D1 delete.

import { embed, validateEmbedInput } from "../embed.js";
import type { Env } from "../types.js";

// ── engagement_remember ───────────────────────────────────────────────────────

export interface RememberBody {
  engagement_id: string;
  content: string;
  session_id?: string;
  tags?: string[];
  vector_recall?: boolean;
}

/**
 * Store an agent memory entry in D1.
 * If vector_recall=true, also embeds and upserts into Vectorize.
 */
export async function handleRemember(body: unknown, env: Env): Promise<Response> {
  if (!body || typeof body !== "object") {
    return Response.json({ error: "VALIDATION_ERROR", message: "Body required" }, { status: 400 });
  }
  const b = body as Record<string, unknown>;

  if (!b["engagement_id"] || typeof b["engagement_id"] !== "string") {
    return Response.json({ error: "VALIDATION_ERROR", message: "engagement_id required" }, { status: 400 });
  }
  if (!b["content"] || typeof b["content"] !== "string") {
    return Response.json({ error: "VALIDATION_ERROR", message: "content required" }, { status: 400 });
  }

  validateEmbedInput(b["content"] as string, "content");

  const engagementId = b["engagement_id"] as string;
  const content = b["content"] as string;
  const sessionId = typeof b["session_id"] === "string" ? b["session_id"] : null;
  const tags = Array.isArray(b["tags"]) ? JSON.stringify(b["tags"]) : "[]";
  const vectorRecall = b["vector_recall"] === true;

  const memoryId = `memory:${crypto.randomUUID()}`;
  const ts = new Date().toISOString();
  let vectorId: string | null = null;

  // Optional vector recall path
  if (vectorRecall) {
    const vector = await embed(content, env);
    await env.VECTORIZE.upsert([
      {
        id: memoryId,
        values: vector,
        namespace: engagementId,
        metadata: { kind: "memory", engagement_id: engagementId },
      },
    ]);
    vectorId = memoryId;
  }

  await env.DB.prepare(
    `INSERT INTO memory (memory_id, engagement_id, session_id, content, tags, vector_id, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(memoryId, engagementId, sessionId, content, tags, vectorId, ts, ts)
    .run();

  return Response.json({ memory_id: memoryId, engagement_id: engagementId }, { status: 201 });
}

// ── engagement_recall ─────────────────────────────────────────────────────────

export interface RecallBody {
  engagement_id: string;
  query?: string;
  session_id?: string;
  top_k?: number;
  vector_recall?: boolean;
}

/**
 * Recall memories by engagement.
 * Vector recall: embed query → Vectorize similarity → JOIN D1.
 * Recency recall (default): D1 ORDER BY created_at DESC LIMIT top_k.
 */
export async function handleRecall(body: unknown, env: Env): Promise<Response> {
  if (!body || typeof body !== "object") {
    return Response.json({ error: "VALIDATION_ERROR", message: "Body required" }, { status: 400 });
  }
  const b = body as Record<string, unknown>;

  if (!b["engagement_id"] || typeof b["engagement_id"] !== "string") {
    return Response.json({ error: "VALIDATION_ERROR", message: "engagement_id required" }, { status: 400 });
  }

  const engagementId = b["engagement_id"] as string;
  const topK = typeof b["top_k"] === "number" && b["top_k"] > 0 ? Math.min(b["top_k"], 50) : 10;
  const sessionId = typeof b["session_id"] === "string" ? b["session_id"] : null;
  const vectorRecall = b["vector_recall"] === true;

  // Vector recall path
  if (vectorRecall) {
    const query = typeof b["query"] === "string" ? b["query"] : "";
    if (!query) {
      return Response.json(
        { error: "VALIDATION_ERROR", message: "query required for vector_recall=true" },
        { status: 400 }
      );
    }
    validateEmbedInput(query, "query");

    const vector = await embed(query, env);
    const matches = await env.VECTORIZE.query(vector, {
      topK,
      returnMetadata: "indexed",
      namespace: engagementId,
      filter: { kind: "memory" },
    });

    const memories: Array<Record<string, unknown>> = [];
    for (const match of matches.matches ?? []) {
      const row = await env.DB.prepare(
        "SELECT * FROM memory WHERE memory_id = ? AND engagement_id = ?"
      )
        .bind(match.id, engagementId)
        .first<Record<string, unknown>>();
      if (!row) continue;
      memories.push({ ...row, score: match.score });
    }
    return Response.json({ memories });
  }

  // Recency recall path (default)
  // session_id filter is optional
  let stmt: D1PreparedStatement;
  if (sessionId !== null) {
    stmt = env.DB.prepare(
      `SELECT * FROM memory WHERE engagement_id = ? AND session_id = ?
       ORDER BY created_at DESC LIMIT ?`
    ).bind(engagementId, sessionId, topK);
  } else {
    stmt = env.DB.prepare(
      `SELECT * FROM memory WHERE engagement_id = ?
       ORDER BY created_at DESC LIMIT ?`
    ).bind(engagementId, topK);
  }

  const { results } = await stmt.all<Record<string, unknown>>();
  return Response.json({ memories: results ?? [] });
}

// ── deleteByIds discipline ────────────────────────────────────────────────────

/**
 * Delete a memory entry.
 * Vectorize delete must succeed before D1 delete — never orphan a live vector.
 */
export async function handleMemoryDelete(memoryId: string, env: Env): Promise<Response> {
  // Check existence
  const row = await env.DB.prepare(
    "SELECT vector_id FROM memory WHERE memory_id = ?"
  )
    .bind(memoryId)
    .first<{ vector_id: string | null }>();

  if (!row) {
    return Response.json({ error: "NOT_FOUND", message: "Memory not found" }, { status: 404 });
  }

  // Delete vector first if it exists
  if (row.vector_id) {
    try {
      await env.VECTORIZE.deleteByIds([row.vector_id]);
    } catch (err) {
      console.error("[siemen/memory] Vectorize delete failed:", (err as Error).message);
      return Response.json(
        { error: "DELETE_FAILED", message: "Vector index error — D1 row preserved" },
        { status: 500 }
      );
    }
  }

  // Safe to delete D1 row now
  await env.DB.prepare("DELETE FROM memory WHERE memory_id = ?").bind(memoryId).run();

  return Response.json({ ok: true, deleted_id: memoryId });
}
