// Findings handlers: engagement_open, engagement_update, engagement_report, finding_store,
// finding_search, finding_batch, finding_update, finding_delete, cache_stats
// Used by both REST routes (src/routes/findings.ts) and MCP tools/call (src/mcp.ts).

import { embed, validateEmbedInput } from "../embed.js";
import type { Env, FindingKind, EngagementStatus, FindingStatus } from "../types.js";

const VALID_KINDS: FindingKind[] = ["finding", "cve", "control"];
const VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"];
const VALID_STATUSES: EngagementStatus[] = ["active", "closed", "archived"];
const VALID_FINDING_STATUSES: FindingStatus[] = ["open", "accepted", "remediated", "false_positive"];

// ── engagement_open ───────────────────────────────────────────────────────────

export interface EngagementOpenBody {
  engagement_id?: string;
  name: string;
  client?: string;
  status?: EngagementStatus;
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

// ── engagement_update (PATCH) ─────────────────────────────────────────────────

export interface EngagementUpdateBody {
  status?: EngagementStatus;
  name?: string;
  client?: string;
}

/**
 * Update engagement status/name/client.
 * When status is set to "archived", also triggers Vectorize namespace cleanup (#14).
 */
export async function handleEngagementUpdate(
  engagementId: string,
  body: unknown,
  env: Env
): Promise<Response> {
  if (!body || typeof body !== "object") {
    return Response.json({ error: "VALIDATION_ERROR", message: "Body required" }, { status: 400 });
  }
  const b = body as Record<string, unknown>;

  // At least one field required
  if (b["status"] === undefined && b["name"] === undefined && b["client"] === undefined) {
    return Response.json(
      { error: "VALIDATION_ERROR", message: "At least one of status, name, client is required" },
      { status: 400 }
    );
  }

  // Validate status enum
  if (b["status"] !== undefined && !VALID_STATUSES.includes(b["status"] as EngagementStatus)) {
    return Response.json(
      { error: "VALIDATION_ERROR", message: `status must be one of: ${VALID_STATUSES.join(", ")}` },
      { status: 400 }
    );
  }

  // Build SET clause dynamically
  const setClauses: string[] = ["updated_at = ?"];
  const bindings: unknown[] = [new Date().toISOString()];

  if (b["status"] !== undefined) {
    setClauses.push("status = ?");
    bindings.push(b["status"]);
  }
  if (b["name"] !== undefined) {
    if (typeof b["name"] !== "string" || b["name"].length === 0) {
      return Response.json({ error: "VALIDATION_ERROR", message: "name must be a non-empty string" }, { status: 400 });
    }
    setClauses.push("name = ?");
    bindings.push(b["name"]);
  }
  if (b["client"] !== undefined) {
    setClauses.push("client = ?");
    bindings.push(b["client"] === null ? null : String(b["client"]));
  }

  bindings.push(engagementId);

  const row = await env.DB.prepare(
    `UPDATE engagements SET ${setClauses.join(", ")} WHERE engagement_id = ? AND deleted_at IS NULL RETURNING *`
  )
    .bind(...bindings)
    .first<Record<string, unknown>>();

  if (!row) {
    return Response.json({ error: "NOT_FOUND", message: "Engagement not found" }, { status: 404 });
  }

  // #14: If archiving, trigger Vectorize namespace cleanup (best-effort)
  if (b["status"] === "archived") {
    void cleanupVectorizeNamespace(engagementId, env);
  }

  return Response.json(row);
}

/**
 * Best-effort Vectorize namespace cleanup for an archived engagement.
 * Queries all vector_ids from findings + memory for this engagement, then batch-deletes.
 * Non-fatal: errors are logged but never bubble to the caller.
 */
async function cleanupVectorizeNamespace(engagementId: string, env: Env): Promise<void> {
  try {
    const [findingRows, memoryRows] = await Promise.all([
      env.DB.prepare(
        "SELECT vector_id FROM findings WHERE engagement_id = ? AND vector_id IS NOT NULL"
      )
        .bind(engagementId)
        .all<{ vector_id: string }>(),
      env.DB.prepare(
        "SELECT vector_id FROM memory WHERE engagement_id = ? AND vector_id IS NOT NULL"
      )
        .bind(engagementId)
        .all<{ vector_id: string }>(),
    ]);

    const ids = [
      ...(findingRows.results ?? []).map((r) => r.vector_id),
      ...(memoryRows.results ?? []).map((r) => r.vector_id),
    ].filter(Boolean);

    if (ids.length > 0) {
      // Vectorize.deleteByIds accepts up to 1000 ids at once
      for (let i = 0; i < ids.length; i += 1000) {
        await env.VECTORIZE.deleteByIds(ids.slice(i, i + 1000));
      }
    }
  } catch (e) {
    console.error("[siemen/findings] Vectorize cleanup failed for engagement", engagementId, (e as Error).message);
  }
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
  tags?: string[];
}

/**
 * Embed a finding/CVE/control and store in Vectorize + D1.
 * Pipeline: validate → embed(title + body) → Vectorize.upsert → D1 insert
 * Returns 409 when external_id already exists for this engagement (#8).
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
  // severity is optional — but if provided it MUST be a valid string enum (not a number)
  if (b["severity"] !== undefined && b["severity"] !== null && typeof b["severity"] !== "string") {
    return Response.json(
      { error: "VALIDATION_ERROR", message: `severity must be one of: ${VALID_SEVERITIES.join(", ")}` },
      { status: 400 }
    );
  }
  if (b["severity"] !== undefined && b["severity"] !== null && !VALID_SEVERITIES.includes(b["severity"] as string)) {
    return Response.json(
      { error: "VALIDATION_ERROR", message: `severity must be one of: ${VALID_SEVERITIES.join(", ")}` },
      { status: 400 }
    );
  }
  const severity = typeof b["severity"] === "string" && VALID_SEVERITIES.includes(b["severity"])
    ? b["severity"]
    : null;
  const asset = typeof b["asset"] === "string" ? b["asset"] : null;
  const externalId = typeof b["external_id"] === "string" ? b["external_id"] : null;
  const metadata = b["metadata"] && typeof b["metadata"] === "object"
    ? JSON.stringify(b["metadata"])
    : "{}";
  const tags = Array.isArray(b["tags"])
    ? JSON.stringify(b["tags"].filter((t) => typeof t === "string"))
    : "[]";

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

  // D1 insert — catch UNIQUE constraint violation on external_id (#8)
  try {
    await env.DB.prepare(
      `INSERT INTO findings (record_id, engagement_id, kind, title, body, severity, asset, external_id, metadata, tags, vector_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(recordId, engagementId, kind, title, bodyText, severity, asset, externalId, metadata, tags, recordId, ts)
      .run();
  } catch (e) {
    const msg = (e as Error).message ?? "";
    if (msg.includes("UNIQUE constraint failed")) {
      return Response.json(
        {
          stored: false,
          duplicate: true,
          message: "Finding with this external_id already exists for this engagement",
        },
        { status: 409 }
      );
    }
    throw e;
  }

  return Response.json({ record_id: recordId, engagement_id: engagementId, kind, stored: true }, { status: 201 });
}

// ── finding_batch ─────────────────────────────────────────────────────────────

export interface FindingBatchBody {
  findings: FindingStoreBody[];
}

/**
 * Batch ingest multiple findings (#1).
 * Processes sequentially — partial success OK.
 * Returns { stored, duplicates, errors: [{ index, error }] }.
 */
export async function handleFindingBatch(body: unknown, env: Env): Promise<Response> {
  if (!body || typeof body !== "object") {
    return Response.json({ error: "VALIDATION_ERROR", message: "Body required" }, { status: 400 });
  }
  const b = body as Record<string, unknown>;

  if (!Array.isArray(b["findings"])) {
    return Response.json({ error: "VALIDATION_ERROR", message: "findings array required" }, { status: 400 });
  }

  // Top-level engagement_id is inherited by each finding if not overridden per-item
  const topLevelEngagementId = typeof b["engagement_id"] === "string" ? b["engagement_id"] : null;

  const items = b["findings"] as unknown[];
  if (items.length === 0) {
    return Response.json({ stored: 0, duplicates: 0, errors: [] });
  }
  if (items.length > 100) {
    return Response.json(
      { error: "VALIDATION_ERROR", message: "Max 100 findings per batch" },
      { status: 400 }
    );
  }

  let stored = 0;
  let duplicates = 0;
  const errors: Array<{ index: number; error: string }> = [];

  for (let i = 0; i < items.length; i++) {
    // Inherit top-level engagement_id if the individual finding omits it
    const item =
      topLevelEngagementId &&
      items[i] &&
      typeof items[i] === "object" &&
      !(items[i] as Record<string, unknown>)["engagement_id"]
        ? { ...(items[i] as Record<string, unknown>), engagement_id: topLevelEngagementId }
        : items[i];
    try {
      const resp = await handleFindingStore(item, env);
      if (resp.status === 201) {
        stored++;
      } else if (resp.status === 409) {
        duplicates++;
      } else {
        const data = await resp.json() as { message?: string };
        errors.push({ index: i, error: data.message ?? `HTTP ${resp.status}` });
      }
    } catch (e) {
      errors.push({ index: i, error: (e as Error).message });
    }
  }

  return Response.json({ stored, duplicates, errors });
}

// ── finding_update (PATCH) ────────────────────────────────────────────────────

/**
 * Update severity/body/tags on a finding (#5).
 * Does not move the Vectorize vector — re-embedding on edit is not yet supported.
 */
export async function handleFindingUpdate(
  recordId: string,
  body: unknown,
  env: Env
): Promise<Response> {
  if (!body || typeof body !== "object") {
    return Response.json({ error: "VALIDATION_ERROR", message: "Body required" }, { status: 400 });
  }
  const b = body as Record<string, unknown>;

  if (b["severity"] === undefined && b["body"] === undefined && b["tags"] === undefined && b["finding_status"] === undefined) {
    return Response.json(
      { error: "VALIDATION_ERROR", message: "At least one of severity, body, tags, finding_status is required" },
      { status: 400 }
    );
  }

  if (
    b["severity"] !== undefined &&
    b["severity"] !== null &&
    !VALID_SEVERITIES.includes(b["severity"] as string)
  ) {
    return Response.json(
      { error: "VALIDATION_ERROR", message: `severity must be one of: ${VALID_SEVERITIES.join(", ")}` },
      { status: 400 }
    );
  }

  if (
    b["finding_status"] !== undefined &&
    !VALID_FINDING_STATUSES.includes(b["finding_status"] as FindingStatus)
  ) {
    return Response.json(
      { error: "VALIDATION_ERROR", message: `finding_status must be one of: ${VALID_FINDING_STATUSES.join(", ")}` },
      { status: 400 }
    );
  }

  const setClauses: string[] = [];
  const bindings: unknown[] = [];

  if (b["severity"] !== undefined) {
    setClauses.push("severity = ?");
    bindings.push(b["severity"] === null ? null : String(b["severity"]));
  }
  if (b["body"] !== undefined) {
    if (typeof b["body"] !== "string" || b["body"].length === 0) {
      return Response.json({ error: "VALIDATION_ERROR", message: "body must be a non-empty string" }, { status: 400 });
    }
    setClauses.push("body = ?");
    bindings.push(b["body"]);
  }
  if (b["tags"] !== undefined) {
    if (!Array.isArray(b["tags"])) {
      return Response.json({ error: "VALIDATION_ERROR", message: "tags must be an array" }, { status: 400 });
    }
    setClauses.push("tags = ?");
    bindings.push(JSON.stringify((b["tags"] as unknown[]).filter((t) => typeof t === "string")));
  }
  if (b["finding_status"] !== undefined) {
    setClauses.push("finding_status = ?");
    bindings.push(String(b["finding_status"]));
  }

  bindings.push(recordId);

  const row = await env.DB.prepare(
    `UPDATE findings SET ${setClauses.join(", ")} WHERE record_id = ? AND deleted_at IS NULL RETURNING *`
  )
    .bind(...bindings)
    .first<Record<string, unknown>>();

  if (!row) {
    return Response.json({ error: "NOT_FOUND", message: "Finding not found" }, { status: 404 });
  }

  // Parse tags back to array for response
  const tagsStr = typeof row["tags"] === "string" ? row["tags"] : "[]";
  let tagsArr: string[] = [];
  try {
    tagsArr = JSON.parse(tagsStr) as string[];
  } catch {
    tagsArr = [];
  }

  return Response.json({ ...row, tags: tagsArr });
}

// ── finding_delete (soft) ─────────────────────────────────────────────────────

/**
 * Soft-delete a finding by setting deleted_at (#9).
 */
export async function handleFindingDelete(recordId: string, env: Env): Promise<Response> {
  const ts = new Date().toISOString();
  const result = await env.DB.prepare(
    `UPDATE findings SET deleted_at = ? WHERE record_id = ? AND deleted_at IS NULL`
  )
    .bind(ts, recordId)
    .run();

  if (result.meta?.changes === 0) {
    return Response.json({ error: "NOT_FOUND", message: "Finding not found" }, { status: 404 });
  }

  return new Response(null, { status: 204 });
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
 * Always filters deleted_at IS NULL.
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

  // JOIN back to D1 for full records — filter soft-deleted rows
  const results: Array<Record<string, unknown>> = [];
  for (const match of matches.matches ?? []) {
    const row = await env.DB.prepare(
      "SELECT * FROM findings WHERE record_id = ? AND engagement_id = ? AND deleted_at IS NULL"
    )
      .bind(match.id, engagementId)
      .first<Record<string, unknown>>();
    if (!row) continue;
    // Parse tags
    const tagsStr = typeof row["tags"] === "string" ? row["tags"] : "[]";
    let tagsArr: string[] = [];
    try { tagsArr = JSON.parse(tagsStr) as string[]; } catch { tagsArr = []; }
    results.push({ ...row, tags: tagsArr, score: match.score });
  }

  return Response.json({ results });
}

// ── cache_stats ───────────────────────────────────────────────────────────────

/**
 * Query semantic_cache_log for hit/miss counts and avg similarity for an engagement.
 * Also returns findings_by_severity rollup (#2).
 */
export async function handleCacheStats(engagementId: string | null, env: Env): Promise<Response> {
  if (!engagementId) {
    return Response.json(
      { error: "VALIDATION_ERROR", message: "engagement_id query param required" },
      { status: 400 }
    );
  }

  const [cacheRow, severityRows] = await Promise.all([
    env.DB.prepare(
      `SELECT
         COUNT(CASE WHEN outcome = 'exact_hit'    THEN 1 END) AS exact_hits,
         COUNT(CASE WHEN outcome = 'semantic_hit' THEN 1 END) AS semantic_hits,
         COUNT(CASE WHEN outcome = 'miss'         THEN 1 END) AS misses,
         AVG(CASE WHEN outcome = 'semantic_hit' THEN similarity END) AS avg_similarity
       FROM semantic_cache_log
       WHERE engagement_id = ?`
    )
      .bind(engagementId)
      .first<{ exact_hits: number; semantic_hits: number; misses: number; avg_similarity: number | null }>(),

    env.DB.prepare(
      `SELECT severity, COUNT(*) AS count
       FROM findings
       WHERE engagement_id = ? AND deleted_at IS NULL
       GROUP BY severity`
    )
      .bind(engagementId)
      .all<{ severity: string | null; count: number }>(),
  ]);

  // Build severity rollup with zero-default for all levels
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const r of severityRows.results ?? []) {
    const key = r.severity ?? "info";
    if (key in bySeverity) bySeverity[key] = r.count;
  }

  return Response.json({
    engagement_id: engagementId,
    exact_hits: cacheRow?.exact_hits ?? 0,
    semantic_hits: cacheRow?.semantic_hits ?? 0,
    misses: cacheRow?.misses ?? 0,
    avg_similarity: cacheRow?.avg_similarity ?? null,
    findings_by_severity: bySeverity,
  });
}

// ── engagement_report (Gap 3: full export) ────────────────────────────────────

/** Max findings returned per page in engagement_report. */
const REPORT_PAGE_SIZE = 200;

/**
 * Full engagement export for report generation / SOC pipeline (Gap 3).
 *
 * Returns:
 *   engagement  — engagement record
 *   findings    — paginated list (all non-deleted), cursor-based
 *   has_more    — true when additional pages exist
 *   next_cursor — opaque base64 cursor for the next page
 *   severity_rollup  — { critical, high, medium, low, info }
 *   status_rollup    — { open, accepted, remediated, false_positive }
 *   memories         — 20 most-recent memory entries
 *   cache_stats      — { exact_hits, semantic_hits, misses }
 *
 * Pagination: ?cursor=<base64>&limit=<n> (max 500 per page).
 * Without cursor: most-recent REPORT_PAGE_SIZE findings.
 */
export async function handleEngagementReport(
  engagementId: string,
  env: Env,
  cursor?: string | null,
  limitParam?: number | null
): Promise<Response> {
  // Verify engagement exists
  const engagement = await env.DB.prepare(
    "SELECT * FROM engagements WHERE engagement_id = ? AND deleted_at IS NULL"
  )
    .bind(engagementId)
    .first<Record<string, unknown>>();

  if (!engagement) {
    return Response.json({ error: "NOT_FOUND", message: "Engagement not found" }, { status: 404 });
  }

  const pageSize = Math.min(
    typeof limitParam === "number" && limitParam > 0 ? limitParam : REPORT_PAGE_SIZE,
    500
  );

  // Fetch findings — cursor-based pagination on (created_at DESC, record_id ASC)
  let findingRows: { results: Record<string, unknown>[] };
  if (cursor) {
    let cursorData: { created_at: string; record_id: string };
    try {
      cursorData = JSON.parse(atob(cursor)) as { created_at: string; record_id: string };
    } catch {
      return Response.json({ error: "VALIDATION_ERROR", message: "Invalid cursor" }, { status: 400 });
    }
    findingRows = await env.DB.prepare(
      `SELECT * FROM findings
       WHERE engagement_id = ? AND deleted_at IS NULL
         AND (created_at < ? OR (created_at = ? AND record_id > ?))
       ORDER BY created_at DESC, record_id ASC
       LIMIT ?`
    )
      .bind(engagementId, cursorData.created_at, cursorData.created_at, cursorData.record_id, pageSize + 1)
      .all<Record<string, unknown>>();
  } else {
    findingRows = await env.DB.prepare(
      `SELECT * FROM findings
       WHERE engagement_id = ? AND deleted_at IS NULL
       ORDER BY created_at DESC
       LIMIT ?`
    )
      .bind(engagementId, pageSize + 1)
      .all<Record<string, unknown>>();
  }

  const allRows = findingRows.results ?? [];
  const hasMore = allRows.length > pageSize;
  const page = hasMore ? allRows.slice(0, pageSize) : allRows;

  // Next cursor from last row in the page
  let nextCursor: string | null = null;
  if (hasMore && page.length > 0) {
    const last = page[page.length - 1];
    nextCursor = btoa(JSON.stringify({ created_at: last["created_at"], record_id: last["record_id"] }));
  }

  // Parse tags in each finding
  const findings = page.map((row) => {
    const tagsStr = typeof row["tags"] === "string" ? row["tags"] : "[]";
    let tagsArr: string[] = [];
    try { tagsArr = JSON.parse(tagsStr) as string[]; } catch { tagsArr = []; }
    return { ...row, tags: tagsArr };
  });

  // Severity + memory + cache rollups in parallel; status rollup degrades gracefully
  // before migration-006 (finding_status column) is applied.
  const [severityRows, memoryRows, cacheRow] = await Promise.all([
    env.DB.prepare(
      `SELECT severity, COUNT(*) AS count FROM findings
       WHERE engagement_id = ? AND deleted_at IS NULL GROUP BY severity`
    )
      .bind(engagementId)
      .all<{ severity: string | null; count: number }>(),

    env.DB.prepare(
      `SELECT memory_id, content, tags, session_id, created_at
       FROM memory WHERE engagement_id = ? ORDER BY created_at DESC LIMIT 20`
    )
      .bind(engagementId)
      .all<Record<string, unknown>>(),

    env.DB.prepare(
      `SELECT
         COUNT(CASE WHEN outcome = 'exact_hit'    THEN 1 END) AS exact_hits,
         COUNT(CASE WHEN outcome = 'semantic_hit' THEN 1 END) AS semantic_hits,
         COUNT(CASE WHEN outcome = 'miss'         THEN 1 END) AS misses
       FROM semantic_cache_log WHERE engagement_id = ?`
    )
      .bind(engagementId)
      .first<{ exact_hits: number; semantic_hits: number; misses: number }>(),
  ]);

  const severityRollup: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const r of severityRows.results ?? []) {
    const key = r.severity ?? "info";
    if (key in severityRollup) severityRollup[key] = r.count;
  }

  // status_rollup — graceful degradation before migration-006 creates finding_status column
  const statusRollup: Record<string, number> = { open: 0, accepted: 0, remediated: 0, false_positive: 0 };
  try {
    const statusRows = await env.DB.prepare(
      `SELECT finding_status, COUNT(*) AS count FROM findings
       WHERE engagement_id = ? AND deleted_at IS NULL GROUP BY finding_status`
    )
      .bind(engagementId)
      .all<{ finding_status: string; count: number }>();
    for (const r of statusRows.results ?? []) {
      if (r.finding_status in statusRollup) statusRollup[r.finding_status] = r.count;
    }
  } catch (e) {
    // Column does not exist yet (migration-006 pending) — or a real query error post-migration
    console.warn("[siemen] status_rollup query failed:", (e as Error).message);
  }

  const memories = (memoryRows.results ?? []).map((row) => {
    const tagsStr = typeof row["tags"] === "string" ? row["tags"] : "[]";
    let tagsArr: string[] = [];
    try { tagsArr = JSON.parse(tagsStr) as string[]; } catch { tagsArr = []; }
    return { ...row, tags: tagsArr };
  });

  return Response.json({
    engagement,
    findings,
    has_more: hasMore,
    next_cursor: nextCursor,
    severity_rollup: severityRollup,
    status_rollup: statusRollup,
    memories,
    cache_stats: {
      exact_hits: cacheRow?.exact_hits ?? 0,
      semantic_hits: cacheRow?.semantic_hits ?? 0,
      misses: cacheRow?.misses ?? 0,
    },
  });
}
