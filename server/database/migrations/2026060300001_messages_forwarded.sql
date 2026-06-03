-- =============================================================
-- messages.forwarded
-- Sender-set boolean flag transported as envelope metadata.
-- Allows the recipient's UI to show a "forwarded" badge without
-- embedding magic bytes inside the encrypted ciphertext payload.
-- Defaults to FALSE so existing rows are unaffected.
-- =============================================================

-- Up Migration

ALTER TABLE messages
  ADD COLUMN forwarded BOOLEAN NOT NULL DEFAULT FALSE;

-- Down Migration

ALTER TABLE messages
  DROP COLUMN forwarded;
