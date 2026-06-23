-- migration-003-findings.sql
-- Finding / CVE / control metadata — authoritative record.
-- vector_id references the Vectorize vector (kind:uuid format).
CREATE TABLE IF NOT EXISTS findings (
  record_id       TEXT PRIMARY KEY,
  engagement_id   TEXT NOT NULL,
  kind            TEXT NOT NULL,              -- finding | cve | control
  title           TEXT NOT NULL,
  body            TEXT NOT NULL,
  severity        TEXT,                       -- critical | high | medium | low | info
  asset           TEXT,                       -- affected host/url/component
  external_id     TEXT,                       -- e.g. CVE-2026-1234
  metadata        TEXT NOT NULL DEFAULT '{}', -- JSON
  vector_id       TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  FOREIGN KEY (engagement_id) REFERENCES engagements(engagement_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id, kind);
CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(engagement_id, severity);
