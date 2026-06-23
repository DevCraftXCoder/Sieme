-- migration-004-semantic-cache-log.sql
-- Observability log for semantic cache hit/miss events.
CREATE TABLE IF NOT EXISTS semantic_cache_log (
  id              TEXT PRIMARY KEY,
  engagement_id   TEXT,
  prompt_hash     TEXT NOT NULL,              -- SHA-256 of normalized prompt (exact-match short-circuit)
  outcome         TEXT NOT NULL,              -- exact_hit | semantic_hit | miss
  similarity      REAL,                       -- cosine score on a semantic_hit
  cache_key       TEXT,                       -- KV key that served / was written
  model           TEXT,
  tokens_saved    INTEGER,                    -- estimated, on a hit
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sclog_engagement ON semantic_cache_log(engagement_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sclog_outcome    ON semantic_cache_log(outcome, created_at DESC);
