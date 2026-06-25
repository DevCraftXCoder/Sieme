-- migration-006: add finding lifecycle status + finding_status index
-- Apply: wrangler d1 execute siemen-db --remote --file migration-006-finding-status.sql

ALTER TABLE findings ADD COLUMN finding_status TEXT NOT NULL DEFAULT 'open'
  CHECK (finding_status IN ('open', 'accepted', 'remediated', 'false_positive'));

CREATE INDEX IF NOT EXISTS idx_findings_status
  ON findings(engagement_id, finding_status)
  WHERE deleted_at IS NULL;
