-- =========================================================
-- 001_srp_auth.sql
-- Replace password_hash with SRP-6a verifier columns.
--
-- The existing schema stores password_hash (Argon2id).
-- SRP replaces this: the server never sees the password.
-- Instead it stores a verifier v = g^x mod N where x is
-- derived client-side using Argon2id (RFC 9106, memory-hard)
-- over the SRP salt, making offline dictionary attacks
-- against a stolen verifier extremely costly.
--
-- Library: secure-remote-password (npm)
--   srp.generateSalt()       → srp_salt  (store on users)
--   srp.deriveVerifier(key)  → srp_verifier (store on users)
--
-- Client derives x with Argon2id (libsodium crypto_pwhash)
-- before calling srp.deriveVerifier — NOT derivePrivateKey
-- directly, which would only apply a bare SHA-256.
-- =========================================================

-- UP:

ALTER TABLE users
    DROP COLUMN password_hash,
    ADD  COLUMN srp_salt     TEXT NOT NULL DEFAULT '',
    ADD  COLUMN srp_verifier TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN users.srp_salt IS
    'Hex-encoded 32-byte random salt (from srp.generateSalt()). '
    'Sent to client in round 1 so it can derive x via Argon2id.';

COMMENT ON COLUMN users.srp_verifier IS
    'Hex-encoded SRP-6a verifier v = g^x mod N '
    '(RFC 5054, 2048-bit group, SHA-256, x derived via Argon2id RFC 9106). '
    'Never transmit to the client.';

-- DOWN:
ALTER TABLE users
    DROP COLUMN IF EXISTS srp_salt,
    DROP COLUMN IF EXISTS srp_verifier,
    ADD COLUMN password_hash VARCHAR(255) NOT NULL;