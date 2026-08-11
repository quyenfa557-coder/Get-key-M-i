-- Optional manual migration.
-- auth-worker.js will also create and backfill this table automatically.

CREATE TABLE IF NOT EXISTS link4m_history (
  license_key TEXT PRIMARY KEY,
  completed_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_link4m_history_completed_at
  ON link4m_history(completed_at);

INSERT OR IGNORE INTO link4m_history (
  license_key,
  completed_at
)
SELECT
  license_key,
  completed_at
FROM link_sessions
WHERE completed_at IS NOT NULL
  AND license_key IS NOT NULL;
