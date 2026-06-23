-- migration-001-engagements.sql
-- Per-engagement tenant table. All other tables FK into this one.
CREATE TABLE IF NOT EXISTS engagements (
  engagement_id   TEXT PRIMARY KEY,          -- caller-supplied or generated UUID
  name            TEXT NOT NULL,
  client          TEXT,
  status          TEXT NOT NULL DEFAULT 'active', -- active | closed | archived
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  deleted_at      TEXT                        -- soft delete
);
