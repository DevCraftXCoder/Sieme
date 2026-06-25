// Env bindings interface — mirrors wrangler.toml bindings
export interface Env {
  // Vectorize index (768-dim, cosine, namespaced per engagement)
  VECTORIZE: Vectorize;
  // D1 database — authoritative metadata + cache log
  DB: D1Database;
  // KV namespace: semantic cache (SC_KV) + fast scratch (KV)
  SC_KV: KVNamespace;
  KV: KVNamespace;
  // Workers AI binding — @cf/baai/bge-base-en-v1.5 embed fallback
  AI: Ai;
  // CF Rate Limiting — namespace 1006
  SIEMEN_RATE_LIMITER: RateLimit;
  // Service binding to llm worker (Worker-to-Worker, bypasses workers.dev restriction)
  LLM_WORKER: Fetcher;

  // Secrets (set via wrangler secret put)
  SIEMEN_API_KEY: string;
  OPENROUTER_API_KEY: string;
  LLM_GATEWAY_KEY: string;

  // [vars] — static config
  LLM_GATEWAY_URL: string;
  OPENROUTER_EMBED_URL: string;
  OLLAMA_EMBED_URL: string;
  HTTP_REFERER: string;
  X_TITLE: string;
}

// Hono context variables (set by middleware)
export interface Variables {
  callerHash: string;
}

// ── Shared domain types ───────────────────────────────────────────────────────

export type FindingKind = "finding" | "cve" | "control";
export type MemoryKind = "memory";
export type VectorKind = FindingKind | "analysis" | MemoryKind;
export type EngagementStatus = "active" | "closed" | "archived";

export interface EngagementRecord {
  engagement_id: string;
  name: string;
  client: string | null;
  status: EngagementStatus;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
}

export type FindingStatus = "open" | "accepted" | "remediated" | "false_positive";

export interface FindingRecord {
  record_id: string;
  engagement_id: string;
  kind: FindingKind;
  title: string;
  body: string;
  severity: string | null;
  status: FindingStatus;
  asset: string | null;
  external_id: string | null;
  metadata: string; // JSON
  tags: string; // JSON
  vector_id: string;
  created_at: string;
  deleted_at: string | null;
  // SIC enrichment (migration-007)
  cwe: string | null;
  owasp_category: string | null;
  cvss_v3: number | null;
  epss: number | null;
  kev: number;
}

export interface MemoryRecord {
  memory_id: string;
  engagement_id: string;
  session_id: string | null;
  content: string;
  tags: string; // JSON array
  vector_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface SemanticCacheLogRow {
  id: string;
  engagement_id: string | null;
  prompt_hash: string;
  outcome: "exact_hit" | "semantic_hit" | "miss";
  similarity: number | null;
  cache_key: string | null;
  model: string | null;
  tokens_saved: number | null;
  created_at: string;
}

export interface EmbedResult {
  values: number[];
  provider: "workers-ai" | "openrouter" | "ollama";
}
