-- =============================================================
-- merkle_roots_state
-- Replace the single broadcast_to_chain boolean with an explicit
-- state machine so the worker can distinguish built / in-flight /
-- confirmed roots without conflating them.  Multiple roots now
-- share one on-chain tx, so the UNIQUE(tx_hash) constraint must
-- be dropped and tx_hash made advisory-only.
-- =============================================================

-- Up Migration

-- 1. Add state + timestamps + retry bookkeeping
ALTER TABLE merkle_roots
  ADD COLUMN state          text         NOT NULL DEFAULT 'built'
                            CHECK (state IN ('built','broadcasting','confirmed','failed')),
  ADD COLUMN created_at     timestamptz  NOT NULL DEFAULT now(),
  ADD COLUMN broadcast_at   timestamptz,
  ADD COLUMN confirmed_at   timestamptz,
  ADD COLUMN block_timestamp bigint,
  ADD COLUMN attempts       int          NOT NULL DEFAULT 0,
  ADD COLUMN log_index      int;

-- 2. Backfill: rows that were already broadcast → confirmed
UPDATE merkle_roots SET state = 'confirmed' WHERE broadcast_to_chain = TRUE;

-- 3. Drop the unique constraint on tx_hash (multiple roots share one tx now)
ALTER TABLE merkle_roots DROP CONSTRAINT merkle_roots_tx_hash_key;

-- 4. Remove the boolean column (replaced by state)
ALTER TABLE merkle_roots DROP COLUMN broadcast_to_chain;

-- 5. Index to drive build/broadcast selects (state + age)
CREATE INDEX idx_merkle_roots_state ON merkle_roots (state, created_at);

-- Down Migration

DROP INDEX idx_merkle_roots_state;

ALTER TABLE merkle_roots
  ADD COLUMN broadcast_to_chain boolean NOT NULL DEFAULT false;

UPDATE merkle_roots SET broadcast_to_chain = TRUE WHERE state = 'confirmed';

ALTER TABLE merkle_roots
  ADD CONSTRAINT merkle_roots_tx_hash_key UNIQUE (tx_hash);

ALTER TABLE merkle_roots
  DROP COLUMN state,
  DROP COLUMN created_at,
  DROP COLUMN broadcast_at,
  DROP COLUMN confirmed_at,
  DROP COLUMN block_timestamp,
  DROP COLUMN attempts,
  DROP COLUMN log_index;
