-- =========================================================
-- 002_srp_challenges.sql
-- In-flight SRP handshake state.
--
-- SRP is a two-round protocol. Between round 1 (server sends
-- salt + serverEphemeral.public) and round 2 (client sends
-- clientSession.proof), the server must retain:
--
--   serverEphemeral.secret  — from srp.generateEphemeral(verifier)
--
-- This is the only value the library needs to call
-- srp.deriveSession() in round 2. It must never be sent to
-- the client or derived from anything the client provides.
--
-- Rows expire after 5 minutes and are hard-deleted on
-- successful authentication by the application handler.
-- =========================================================

-- UP:

CREATE TABLE srp_challenges (
    id                UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),

    user_id           UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- serverEphemeral.secret from srp.generateEphemeral(verifier).
    -- Never transmitted to the client.
    srp_server_secret BYTEA        NOT NULL,

    created_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at        TIMESTAMPTZ NOT NULL
                          DEFAULT (CURRENT_TIMESTAMP + INTERVAL '5 minutes')
);

CREATE INDEX idx_srp_challenges_user
    ON srp_challenges (user_id, expires_at);

CREATE OR REPLACE FUNCTION cleanup_srp_challenges()
RETURNS void AS $$
BEGIN
    DELETE FROM srp_challenges WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- DOWN:

DROP FUNCTION IF EXISTS cleanup_srp_challenges();
DROP TABLE    IF EXISTS srp_challenges;