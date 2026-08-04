CREATE TABLE IF NOT EXISTS keys (
  license_key TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'active',
  expires_at INTEGER NOT NULL,
  device_bound TEXT,
  used INTEGER NOT NULL DEFAULT 0,
  max_uses INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  note TEXT
);

CREATE INDEX IF NOT EXISTS idx_keys_status
  ON keys(status);

CREATE INDEX IF NOT EXISTS idx_keys_expires_at
  ON keys(expires_at);

CREATE INDEX IF NOT EXISTS idx_keys_device_bound
  ON keys(device_bound);

CREATE TABLE IF NOT EXISTS link_sessions (
  session_hash TEXT PRIMARY KEY,
  license_key TEXT NOT NULL,
  device_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  completed_at INTEGER,
  FOREIGN KEY (license_key) REFERENCES keys(license_key)
);

CREATE INDEX IF NOT EXISTS idx_link_sessions_license_key
  ON link_sessions(license_key);

CREATE INDEX IF NOT EXISTS idx_link_sessions_expires_at
  ON link_sessions(expires_at);
