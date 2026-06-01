-- 2026060100002_opk_pairing_device_sessions_msg_seq.sql
-- Sync the live schema with structural changes that landed directly in
-- schema.sql (OPK pairing + device_sessions), plus convert msg_sequence to a
-- DB sequence so it is monotonic and collision-free under concurrency.
--
-- All statements are guarded so running this on a fresh schema.sql database
-- (which already has these objects) is a harmless no-op.

-- ── one_time_prekeys: paired X25519 / ML-KEM one-time prekeys ──
ALTER TABLE one_time_prekeys
    ADD COLUMN IF NOT EXISTS opk_id   INTEGER     NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS key_type VARCHAR(20) NOT NULL DEFAULT 'x25519';

ALTER TABLE one_time_prekeys
    ADD CONSTRAINT one_time_prekeys_key_type_check
        CHECK (key_type IN ('x25519', 'ml-kem-1024')),
    ADD CONSTRAINT one_time_prekeys_device_opk_type_key
        UNIQUE (device_id, opk_id, key_type);

-- Rebuild the partial lookup index to include key_type.
DROP INDEX IF EXISTS idx_opk_lookup;
CREATE INDEX idx_opk_lookup
    ON one_time_prekeys(device_id, key_type)
    WHERE used = FALSE;

-- ── device_sessions: persist SRP session keys across server restarts ──
CREATE TABLE IF NOT EXISTS device_sessions (
    device_id UUID PRIMARY KEY
        REFERENCES devices(id) ON DELETE CASCADE,
    session_key_hex TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_sessions_expiry
    ON device_sessions(expires_at);

-- ── message_queue.msg_sequence: monotonic DB sequence ──
-- Replaces the application-side Date.now()+Math.random() value with nextval(),
-- which is atomic, strictly increasing, and never collides.
CREATE SEQUENCE IF NOT EXISTS message_queue_msg_sequence_seq;
ALTER SEQUENCE message_queue_msg_sequence_seq
    OWNED BY message_queue.msg_sequence;
ALTER TABLE message_queue
    ALTER COLUMN msg_sequence SET DEFAULT nextval('message_queue_msg_sequence_seq');
