-- =============================================================
-- message_hidden
-- Per-user "delete for me" layer, independent of the global
-- messages.deleted_at (which covers "delete for everyone").
-- Hiding a message gates proof retrieval for that user only;
-- all other participants are unaffected.  The on-chain anchor
-- is never removed — deletion/hiding gates proof *material*
-- only; the immutable anchor is preserved.
-- =============================================================

-- Up Migration

CREATE TABLE message_hidden (
  msg_id      uuid        NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id     uuid        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  hidden_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (msg_id, user_id)
);

-- Down Migration

DROP TABLE message_hidden;
