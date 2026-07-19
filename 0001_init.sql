CREATE TABLE IF NOT EXISTS keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_key TEXT NOT NULL UNIQUE,
  plan_hours INTEGER NOT NULL CHECK (plan_hours IN (12, 24)),
  device_hash TEXT,
  created_at INTEGER NOT NULL,
  claimed_at INTEGER,
  expires_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked'))
);

CREATE INDEX IF NOT EXISTS idx_keys_license_key ON keys(license_key);
CREATE INDEX IF NOT EXISTS idx_keys_device_hash ON keys(device_hash);
CREATE INDEX IF NOT EXISTS idx_keys_expires_at ON keys(expires_at);
