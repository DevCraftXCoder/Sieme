// Findings handlers: engagement_open, finding_store, finding_search, cache_stats
// Used by both REST routes (src/routes/findings.ts) and MCP tools/call (src/mcp.ts).

import { embed, validateEmbedInput } from "../embed.js";
import type { Env, FindingKind } from "../types.js";

const VALID_KINDS: FindingKind[] = ["finding", "cve", "control"];
const VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"];

// ── engagement_open ───────────────────────────────────────────────────────────

export interface EngagementOpenBody {
  engagement_id?: string;
  name: string;
  client?: string;
  status?: "active" | "closed" | "archived";
}

/**
 * Create or upsert an engagement record in D1.
 * engagement_id may be caller-supplied or auto-generated.
 */
export async function handleEngagementOpen(body: unknown, env: Env): Promise<Response> {
  if (!body || typeof body !== "object") {
    return Response.json({ error: "VALIDATION_ERROR", message: "Body required" }, { status: 400 });
  }
  const b = body as Record<string, unknown>;

  if (!b["name"] || typeof b["name"] !== "string") {
    return Response.json({ error: "VALIDATION_ERROR", message: "name is required" }, { status: 400 });
  }

  const ts = new Date().toISOString();
  const engagementId =
    typeof b["engagement_id"] === "string" && b["engagement_id"].length > 0
      ? b["engagement_id"]
      : crypto.randomUUID();
  const status = typeof b["status"] === "string" ? b["status"] : "active";
  const client = typeof b["client"] === "string" ? b["client"] : null;

  // Upsert — create if not exists, skip if engagement_id already registered
  await env.DB.prepare(
    `INSERT INTO engagements (engagement_id, name, client, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(engagement_id) DO UPDATE SET
       name = excluded.name,
       client = excluded.client,
       status = excluded.status,
       updated_at = excluded.updated_at`
  )
    .bind(engagementId, b["name"], client, status, ts, ts)
    .run();

  return Response.json(
    { engagement_id: engagementId, name: b["name"], status, client, created_at: ts },
    { status: 201 }
  );
}

// ── finding_store ─────────────────────────────────────────────────────────────

export interface FindingStoreBody {
  engagement_id: string;
  kind: FindingKind;
  title: string;
  body: string;
  severity?: string;
  asset?: string;
  external_id?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Embed a finding/CVE/control and store in Vectorize + D1.
 * Pipeline: validate → embed(title + body) → Vectorize.upsert → D1 insert
 */
export async function handleFindingStore(body: unknown, env: Env): Promise<Response> {
  if (!body || typeof body !== "object") {
    return Response.json({ error: "VALIDATION_ERROR", message: "Body required" }, { status: 400 });
  }
  const b = body as Record<string, unknown>;

  // Required fields
  if (!b["engagement_id"] || typeof b["engagement_id"] !== "string") {
    return Response.json({ error: "VALIDATION_ERROR", message: "engagement_id required" }, { status: 400 });
  }
  if (!b["kind"] || !VALID_KINDS.includes(b["kind"] as FindingKind)) {
    return Response.json(
      { error: "VALIDATION_ERROR", message: `kind must be one of: ${VALID_KINDS.join(", ")}` },
      { status: 400 }
    );
  }
  if (!b["title"] || typeof b["title"] !== "string") {
    return Response.json({ error: "VALIDATION_ERROR", message: "title required" }, { status: 400 });
  }
  if (!b["body"] || typeof b["body"] !== "string") {
    return Response.json({ error: "VALIDATION_ERROR", message: "body required" }, { status: 400 });
  }

  const kind = b["kind"] as FindingKind;
  const engagementId = b["engagement_id"] as string;
  const title = b["title"] as string;
  const bodyText = b["body"] as string;
  const severity = typeof b["severity"] === "string" && VALID_SEVERITIES.includes(b["severity"])
    ? b["severity"]
    : null;
  const asset = typeof b["asset"] === "string" ? b["asset"] : null;
  const externalId = typeof b["external_id"] === "string" ? b["external_id"] : null;
  const metadata = b["metadata"] && typeof b["metadata"] === "object"
    ? JSON.stringify(b["metadata"])
    : "{}";

  // Validate + embed the combined text (cap 2000 chars)
  const embedText = `${title} ${bodyText}`.slice(0, 2000);
  validateEmbedInput(embedText, "title+body");

  const vector = await embed(embedText, env);

  // ID convention: <kind>:<uuid>
  const recordId = `${kind}:${crypto.randomUUID()}`;
  const ts = new Date().toISOString();

  // Vectorize upsert (namespace = engagement_id for hard tenant isolation)
  await env.VECTORIZE.upsert([
    {
      id: recordId,
      values: vector,
      namespace: engagementId,
      metadata: { kind, engagement_id: engagementId, severity: severity ?? "", record_id: recordId },
    },
  ]);

  // D1 insert
  await env.DB.prepare(
    `INSERT INTO findings (record_id, engagement_id, kind, title, body, severity, asset, external_id, metadata, vector_id, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(recordId, engagementId, kind, title, bodyText, severity, asset, externalId, metadata, recordId, ts)
    .run();

  return Response.json({ record_id: recordId, engagement_id: engagementId, kind }, { status: 201 });
}

// ── finding_search ────────────────────────────────────────────────────────────

export interface FindingSearchBody {
  engagement_id: string;
  query: string;
  kind?: FindingKind;
  top_k?: number;
}

/**
 * Semantic RAG over findings/CVEs/controls in an engagement.
 * Namespace-isolated: never returns another engagement's findings.
 */
export async function handleFindingSearch(body: unknown, env: Env): Promise<Response> {
  if (!body || typeof body !== "object") {
    return Response.json({ error: "VALIDATION_ERROR", message: "Body required" }, { status: 400 });
  }
  const b = body as Record<string, unknown>;

  if (!b["engagement_id"] || typeof b["engagement_id"] !== "string") {
    return Response.json({ error: "VALIDATION_ERROR", message: "engagement_id required" }, { status: 400 });
  }
  if (!b["query"] || typeof b["query"] !== "string") {
    return Response.json({ error: "VALIDATION_ERROR", message: "query required" }, { status: 400 });
  }

  const engagementId = b["engagement_id"] as string;
  const query = b["query"] as string;
  const topK = typeof b["top_k"] === "number" && b["top_k"] > 0 ? Math.min(b["top_k"], 20) : 5;
  const kindFilter = b["kind"] && VALID_KINDS.includes(b["kind"] as FindingKind)
    ? (b["kind"] as FindingKind)
    : undefined;

  validateEmbedInput(query, "query");
  const vector = await embed(query, env);

  // Query Vectorize — namespace-scoped to engagement_id
  const queryOptions: VectorizeQueryOptions = {
    topK,
    returnMetadata: "indexed",
    namespace: engagementId,
  };
  if (kindFilter) {
    queryOptions.filter = { kind: kindFilter };
  }

  const matches = await env.VECTORIZE.query(vector, queryOptions);

  // JOIN back to D1 for full records
  const results: Array<Record<string, unknown>> = [];
  for (const match of matches.matches ?? []) {
    const row = await env.DB.prepare(
      "SELECT * FROM findings WHERE record_id = ? AND engagement_id = ?"
    )
      .bind(match.id, engagementId)
      .first<Record<string, unknown>>();
    if (!row) continue;
    results.push({ ...row, score: match.score });
  }

  return Response.json({ results });
}

// ── cache_stats ───────────────────────────────────────────────────────────────

/**
 * Query semantic_cache_log for hit/miss counts and avg similarity for an engagement.
 */
export async function handleCacheStats(engagementId: string | null, env: Env): Promise<Response> {
  if (!engagementId) {
    return Response.json(
      { error: "VALIDATION_ERROR", message: "engagement_id query param required" },
      { status: 400 }
    );
  }

  const row = await env.DB.prepare(
    `SELECT
       COUNT(CASE WHEN outcome = 'exact_hit'    THEN 1 END) AS exact_hits,
       COUNT(CASE WHEN outcome = 'semantic_hit' THEN 1 END) AS semantic_hits,
       COUNT(CASE WHEN outcome = 'miss'         THEN 1 END) AS misses,
       AVG(CASE WHEN outcome = 'semantic_hit' THEN similarity END) AS avg_similarity
     FROM semantic_cache_log
     WHERE engagement_id = ?`
  )
    .bind(engagementId)
    .first<{ exact_hits: number; semantic_hits: number; misses: number; avg_similarity: number | null }>();

  return Response.json({
    engagement_id: engagementId,
    exact_hits: row?.exact_hits ?? 0,
    semantic_hits: row?.semantic_hits ?? 0,
    misses: row?.misses ?? 0,
    avg_similarity: row?.avg_similarity ?? null,
  });
}
