-- =============================================================
-- merkle_leaves
-- Per-message leaf tracking.  Each message gets exactly one leaf
-- (UNIQUE msg_id).  The leaf transitions pending → batched when
-- included in a built root, then → confirmed when that root is
-- confirmed on-chain.  ON DELETE CASCADE keeps leaves in sync
-- with message hard-deletes; soft-deletes gate proof retrieval
-- at the application layer without touching this table.
-- =============================================================

-- Up Migration

CREATE TABLE merkle_leaves (
  id              serial       PRIMARY KEY,
  leaf_hash       char(66)     NOT NULL,
  msg_id          uuid         NOT NULL UNIQUE
                               REFERENCES messages(id) ON DELETE CASCADE,
  merkle_root_id  int          REFERENCES merkle_roots(id),
  leaf_index      int,
  state           text         NOT NULL DEFAULT 'pending'
                               CHECK (state IN ('pending','batched','confirmed')),
  created_at      timestamptz  NOT NULL DEFAULT now()
);

-- Fetch the N oldest pending leaves efficiently
CREATE INDEX idx_merkle_leaves_pending ON merkle_leaves (created_at)
  WHERE state = 'pending';

-- Reconstruct the ordered leaf list for a given root
CREATE INDEX idx_merkle_leaves_root ON merkle_leaves (merkle_root_id, leaf_index);

-- Down Migration

DROP TABLE merkle_leaves;
