-- Sent Tweaks VIP marker table.
-- Safe to run more than once.
-- auth-worker.js also creates this table automatically if missing.

CREATE TABLE IF NOT EXISTS vip_keys (
  license_key TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  note TEXT
);

CREATE INDEX IF NOT EXISTS idx_vip_keys_created_at
  ON vip_keys(created_at);
