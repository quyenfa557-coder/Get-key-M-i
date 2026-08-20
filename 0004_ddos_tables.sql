-- Sent Tweaks Sentinel persistence.
-- Normal request counters live in Cloudflare's Rate Limiting binding.
-- D1 stores only temporary blocks and security events.

CREATE TABLE IF NOT EXISTS sentinel_blocklist (
  client_key TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  blocked_at INTEGER NOT NULL,
  expires_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_sentinel_blocklist_expires_at
  ON sentinel_blocklist(expires_at);

CREATE TABLE IF NOT EXISTS sentinel_attack_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_key TEXT NOT NULL,
  reason TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  user_agent TEXT,
  path TEXT,
  cf_ray TEXT,
  country TEXT
);

CREATE INDEX IF NOT EXISTS idx_sentinel_attack_logs_timestamp
  ON sentinel_attack_logs(timestamp);

CREATE INDEX IF NOT EXISTS idx_sentinel_attack_logs_reason_timestamp
  ON sentinel_attack_logs(reason, timestamp);
