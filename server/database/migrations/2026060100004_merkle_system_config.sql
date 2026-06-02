-- =============================================================
-- merkle_system_config
-- Runtime-tunable Merkle anchoring constants stored in the
-- existing system_config key/value table.  The server reads
-- these at startup and falls back to the code-mirrored constants
-- in server/constants/blockchain.js if any row is missing.
--
-- Key                          | Value   | Unit / meaning
-- -----------------------------|---------|-----------------------------
-- merkle_batch_size            | 100     | messages per root
-- merkle_root_build_interval_ms| 300000  | ms — build partial root
-- merkle_broadcast_interval_ms | 1200000 | ms — broadcast built roots
-- merkle_broadcast_min_roots   | 4       | broadcast early once >= this many roots built
-- merkle_max_roots_per_tx      | 100     | hard cap = contract MAX_BATCH_SIZE
-- merkle_worker_tick_ms        | 60000   | ms — worker wake cadence
-- merkle_max_broadcast_attempts| 5       | retry cap → failed
-- =============================================================

-- Up Migration

INSERT INTO system_config (key, value) VALUES
  ('merkle_batch_size',             '100'),
  ('merkle_root_build_interval_ms', '300000'),
  ('merkle_broadcast_interval_ms',  '1200000'),
  ('merkle_broadcast_min_roots',    '4'),
  ('merkle_max_roots_per_tx',       '100'),
  ('merkle_worker_tick_ms',         '60000'),
  ('merkle_max_broadcast_attempts', '5')
ON CONFLICT (key) DO NOTHING;

-- Down Migration

DELETE FROM system_config WHERE key LIKE 'merkle_%';
