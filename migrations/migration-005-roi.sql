-- ROI improvements: tags column + external_id dedup index + soft delete
ALTER TABLE findings ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';
ALTER TABLE findings ADD COLUMN deleted_at TEXT DEFAULT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_external_id
  ON findings(engagement_id, external_id)
  WHERE external_id IS NOT NULL;
