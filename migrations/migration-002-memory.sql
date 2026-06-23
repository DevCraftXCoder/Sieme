-- migration-002-memory.sql
-- Per-engagement agent memory (remember / recall).
CREATE TABLE IF NOT EXISTS memory (
  memory_id       TEXT PRIMARY KEY,
  engagement_id   TEXT NOT NULL,
  session_id      TEXT,                       -- optional sub-scope within an engagement
  content         TEXT NOT NULL,
  tags            TEXT NOT NULL DEFAULT '[]', -- JSON array
  vector_id       TEXT,                       -- nullable: set when vector recall is enabled
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  FOREIGN KEY (engagement_id) REFERENCES engagements(engagement_id)
);
CREATE INDEX IF NOT EXISTS idx_memory_engagement ON memory(engagement_id, session_id);
CREATE INDEX IF NOT EXISTS idx_memory_created   ON memory(engagement_id, created_at DESC);
