-- Sentinel V2: analytics-only indexes.
-- No per-request counters are stored in D1.

CREATE INDEX IF NOT EXISTS idx_sentinel_attack_logs_client_timestamp
  ON sentinel_attack_logs(client_key, timestamp);

CREATE INDEX IF NOT EXISTS idx_sentinel_attack_logs_path_timestamp
  ON sentinel_attack_logs(path, timestamp);
