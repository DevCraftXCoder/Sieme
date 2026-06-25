-- migration-007: add SIC enrichment columns to findings (cwe, owasp, cvss, epss, kev) + owasp index
-- Apply: wrangler d1 execute siemen-db --remote --file migration-007-finding-enrichment.sql
-- NOTE: D1/SQLite cannot add multiple columns in one ALTER — one ALTER TABLE per column.

ALTER TABLE findings ADD COLUMN cwe TEXT;
ALTER TABLE findings ADD COLUMN owasp_category TEXT;
ALTER TABLE findings ADD COLUMN cvss_v3 REAL;
ALTER TABLE findings ADD COLUMN epss REAL;
ALTER TABLE findings ADD COLUMN kev INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_findings_owasp
  ON findings(engagement_id, owasp_category)
  WHERE deleted_at IS NULL;
