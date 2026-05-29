-- =========================================================
-- POSTGRESQL SECURE MESSAGING DATABASE
-- Signal-Style TOFU Architecture
-- Hybrid Classical + Optional PQ E2EE
-- Blockchain Merkle Root Verification
-- =========================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =========================================================
-- CONFIGURATION
-- =========================================================

CREATE TABLE system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO system_config(key, value)
VALUES
('max_queue_messages_per_device', '1000'),
('message_expiry_hours', '168'),
('signed_prekey_rotation_days', '30'),
('opk_low_watermark', '25');

-- =========================================================
-- USERS
-- =========================================================

CREATE TABLE users (
    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),

    username VARCHAR(50)
        UNIQUE
        NOT NULL,

    -- Argon2id hash ONLY
    password_hash VARCHAR(255)
        NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    last_seen TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    account_status VARCHAR(20)
        NOT NULL DEFAULT 'active',

    CHECK (
        account_status IN (
            'active',
            'disabled',
            'locked'
        )
    )
);

CREATE INDEX idx_users_username
    ON users(username);

-- =========================================================
-- DEVICES
-- =========================================================

CREATE TABLE devices (
    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),

    user_id UUID
        NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    device_name VARCHAR(100),

    -- =====================================================
    -- CLASSICAL IDENTITY KEY
    -- X25519
    -- =====================================================

    idk_classical_pub BYTEA
        NOT NULL,

    -- =====================================================
    -- OPTIONAL PQ IDENTITY KEY
    -- ML-KEM / Kyber
    -- =====================================================

    idk_pq_pub BYTEA,

    -- =====================================================
    -- SIGNING KEY
    -- Ed25519 OR ML-DSA
    -- =====================================================

    identity_signing_pub BYTEA
        NOT NULL,

    -- =====================================================
    -- SIGNED PREKEY
    -- =====================================================

    signed_prekey_pub BYTEA
        NOT NULL,

    signed_prekey_signature BYTEA
        NOT NULL,

    signed_prekey_created_at TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- =====================================================
    -- LAST RESORT ONE-TIME PREKEY
    -- Used when the OPK pool is exhausted.
    -- Unlike regular OPKs this key is never consumed;
    -- it stays in place until the device rotates it.
    -- The signature proves it was legitimately registered
    -- by this device (same model as signed_prekey_signature).
    -- =====================================================

    last_resort_opk_pub BYTEA,

    last_resort_opk_signature BYTEA,

    last_resort_opk_created_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    last_seen TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    revoked BOOLEAN
        NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_devices_user
    ON devices(user_id)
    WHERE revoked = FALSE;

CREATE INDEX idx_devices_active
    ON devices(id)
    WHERE revoked = FALSE;

-- =========================================================
-- ONE-TIME PREKEYS
-- =========================================================

CREATE TABLE one_time_prekeys (
    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),

    device_id UUID
        NOT NULL
        REFERENCES devices(id)
        ON DELETE CASCADE,

    opk_pub BYTEA
        NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    used BOOLEAN
        NOT NULL DEFAULT FALSE,

    used_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_opk_lookup
    ON one_time_prekeys(device_id)
    WHERE used = FALSE;

-- =========================================================
-- CONVERSATIONS
-- =========================================================

CREATE TABLE conversations (
    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),

    created_at TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- =========================================================
-- CONVERSATION MEMBERS
-- =========================================================

CREATE TABLE conversation_members (
    conversation_id UUID
        NOT NULL
        REFERENCES conversations(id)
        ON DELETE CASCADE,

    user_id UUID
        NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    joined_at TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (
        conversation_id,
        user_id
    )
);

CREATE INDEX idx_conversation_members_user
    ON conversation_members(user_id);

-- =========================================================
-- MESSAGES
--
-- The permanent record of every logical message.
-- Ciphertext lives here, not in the queue.
--
-- ARCHITECTURE RATIONALE
-- ----------------------
-- message_queue is a transient, per-device delivery
-- envelope store: it routes ciphertext to devices and
-- then purges itself.  If ciphertext only lived in the
-- queue, the sender would have NO long-term record of
-- what they sent once every recipient has ACK'd.
--
-- Keeping ciphertext on messages gives:
--   - One authoritative encrypted copy per logical message.
--   - A stable anchor for the Merkle / blockchain hash.
--   - The sender's persistent message history (they can
--     re-derive or re-display the plaintext locally using
--     their own copy of the symmetric key).
--
-- E2EE note: the ciphertext here is encrypted to the
-- RECIPIENT(S). The server cannot read it even though it
-- stores it long-term. This is exactly how Signal/WhatsApp
-- work: the server stores ciphertext it cannot decrypt.
--
-- [FIX: SOFT-DELETE]
-- deleted_at + deleted_by_device_id implement the "delete
-- message" operation required by the brief.
--
-- Why soft-delete and not hard-delete?
--   - Hard-deleting the row cascades into message_queue
--     and wipes the delivery envelope before the recipient
--     can receive it.  That is a different operation
--     (message retraction / revocation) and needs
--     explicit design.
--   - Soft-delete lets the server record WHO deleted WHEN
--     without destroying in-flight delivery state.
--   - The application layer enforces that only the sender
--     may set deleted_at (see ACCESS CONTROL note below).
--   - A separate retention policy can hard-delete rows
--     where deleted_at IS NOT NULL after a grace period.
--
-- ACCESS CONTROL FOR DELETE
-- -------------------------
-- The application must enforce sender-only deletion.
-- Use this parameterised pattern:
--
--   UPDATE messages
--   SET    deleted_at          = NOW(),
--          deleted_by_device_id = $requesting_device_id
--   WHERE  id                  = $message_id
--     AND  sender_device_id IN (
--            SELECT id FROM devices WHERE user_id = $requesting_user_id
--          )
--     AND  deleted_at IS NULL;   -- idempotent: no-op if already deleted
--
-- This must run inside the authenticated request handler
-- AFTER verifying the session belongs to $requesting_user_id.
-- Never accept $requesting_user_id from the client payload.
-- =========================================================

CREATE TABLE messages (
    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),

    conversation_id UUID
        NOT NULL
        REFERENCES conversations(id)
        ON DELETE CASCADE,

    sender_device_id UUID
        NOT NULL
        REFERENCES devices(id),

    -- =====================================================
    -- ENCRYPTED PAYLOAD (permanent record)
    --
    -- One ciphertext per logical message, encrypted to the
    -- recipient(s).  The server stores but cannot decrypt.
    -- Wiped only when the sender explicitly deletes the
    -- message (deleted_at IS NOT NULL) and a retention
    -- job runs; NOT wiped on delivery acknowledgment
    -- (that is message_queue's concern).
    --
    -- ChaCha20-Poly1305 or AES-256-GCM depending on the
    -- AEAD negotiated during key establishment.
    -- =====================================================

    ciphertext BYTEA
        NOT NULL,

    nonce BYTEA
        NOT NULL,

    -- =====================================================
    -- AUTHENTICATED METADATA
    -- Bound into the AEAD tag to prevent envelope swapping.
    -- Includes: sender_device_id, conversation_id, created_at
    -- (encoded by the client before encryption).
    -- =====================================================

    associated_data BYTEA
        NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- =====================================================
    -- SOFT DELETE
    -- =====================================================

    deleted_at TIMESTAMP WITH TIME ZONE,

    deleted_by_device_id UUID
        REFERENCES devices(id),

    -- Both fields must be set together or not at all.
    CHECK (
        (deleted_at IS NULL AND deleted_by_device_id IS NULL)
        OR
        (deleted_at IS NOT NULL AND deleted_by_device_id IS NOT NULL)
    ),

    -- =====================================================
    -- PAYLOAD AND NONCE SIZE CONSTRAINTS
    -- =====================================================

    CHECK (octet_length(ciphertext) <= 65536),

    -- ChaCha20-Poly1305: 12-byte nonce
    -- AES-256-GCM:       12-byte nonce (96-bit, recommended)
    CHECK (octet_length(nonce) = 12)
);

CREATE INDEX idx_messages_conversation
    ON messages(
        conversation_id,
        created_at ASC
    )
    WHERE deleted_at IS NULL;

-- Partial index for soft-delete audit queries.
CREATE INDEX idx_messages_deleted
    ON messages(deleted_at)
    WHERE deleted_at IS NOT NULL;

-- =========================================================
-- MERKLE ROOTS
-- Blockchain Verification Anchors
--
-- Hash algorithm: keccak256.
-- Must match the on-chain Solidity contract which uses
-- Solidity's built-in keccak256().

-- Merkle roots submitted to the MessageIntegrity contract on Sepolia.
-- Verify by calling validateRoot(bytes32) on-chain; retrieve the
-- timestamp via the HashStored event using tx_hash.
-- =========================================================

CREATE TABLE merkle_roots (
    id SERIAL PRIMARY KEY,

    -- 0x-prefixed keccak256 root. Strip '0x' before passing to contract.
    merkle_root CHAR(66)
        NOT NULL
        UNIQUE,

    -- Set once ethers.js returns the transaction hash after broadcast.
    tx_hash CHAR(66)
        UNIQUE,

    -- TRUE once the transaction has been broadcast to Sepolia.
    broadcast_to_chain BOOLEAN
        NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_merkle_roots_tx
    ON merkle_roots(tx_hash)
    WHERE tx_hash IS NOT NULL;

-- =========================================================
-- MESSAGE QUEUE
--
-- Per-device delivery routing table.
--
-- ARCHITECTURE RATIONALE
-- ----------------------
-- The queue's job is narrow and transient:
--   1. Tell the server which devices still need this message.
--   2. Track delivery state (pending → delivered → acknowledged).
--   3. Enforce replay protection via (device, sequence) unique index.
--   4. Carry per-device associated_data (recipient device ID,
--      sequence number) that differs across fanout recipients.
--
-- The queue does NOT store ciphertext.  Ciphertext now lives
-- on messages.  The server assembles the full delivery
-- envelope for a recipient by JOIN-ing:
--
--   SELECT m.ciphertext, m.nonce, mq.associated_data,
--          mq.msg_sequence, mq.expires_at
--   FROM   message_queue mq
--   JOIN   messages m ON m.id = mq.msg_id
--   WHERE  mq.recipient_device_id = $device_id
--     AND  mq.delivery_state      = 'pending'
--   ORDER  BY mq.msg_sequence;
--
-- After ACK the queue row is deleted immediately (it no longer
-- carries data worth retaining).  The messages row persists.
-- =========================================================

CREATE TABLE message_queue (
    id UUID PRIMARY KEY
        DEFAULT uuid_generate_v4(),

    msg_id UUID
        NOT NULL
        REFERENCES messages(id)
        ON DELETE CASCADE,

    recipient_device_id UUID
        NOT NULL
        REFERENCES devices(id)
        ON DELETE CASCADE,

    -- =====================================================
    -- PER-DEVICE AUTHENTICATED METADATA
    -- Differs per fanout recipient (recipient device ID,
    -- sequence number, timestamp).  Bound into the AEAD
    -- tag by the client when verifying the envelope.
    -- =====================================================

    associated_data BYTEA
        NOT NULL,

    -- =====================================================
    -- MESSAGE ORDERING / REPLAY PROTECTION
    -- =====================================================

    msg_sequence BIGINT
        NOT NULL,

    queued_at TIMESTAMP WITH TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    delivered_at TIMESTAMP WITH TIME ZONE,

    acknowledged_at TIMESTAMP WITH TIME ZONE,

    expires_at TIMESTAMP WITH TIME ZONE
        NOT NULL,

    delivery_state VARCHAR(20)
        NOT NULL DEFAULT 'pending',

    CHECK (
        delivery_state IN (
            'pending',
            'delivered',
            'acknowledged',
            'expired',
            'failed'
        )
    )
);

-- =========================================================
-- REPLAY PROTECTION
-- Prevent duplicate sequence insertion
-- =========================================================

CREATE UNIQUE INDEX idx_queue_sequence_unique
    ON message_queue(
        recipient_device_id,
        msg_sequence
    );

CREATE INDEX idx_queue_delivery
    ON message_queue(
        recipient_device_id,
        delivery_state,
        queued_at
    );

CREATE INDEX idx_queue_expiry
    ON message_queue(expires_at);

CREATE INDEX idx_queue_message
    ON message_queue(msg_id);

-- =========================================================
-- FANOUT ENDPOINT DISCOVERY
-- =========================================================

/*

PARAMETERS:

$1 = conversation_id
$2 = sender_device_id

SELECT
    d.id AS device_id,

    d.user_id,

    d.identity_signing_pub,

    d.idk_classical_pub,

    d.idk_pq_pub,

    d.signed_prekey_pub,

    d.signed_prekey_signature,

    d.last_resort_opk_pub,

    d.last_resort_opk_signature

FROM devices d

JOIN conversation_members cm
    ON d.user_id = cm.user_id

WHERE cm.conversation_id = $1
  AND d.revoked = FALSE
  AND d.id != $2;

*/

-- =========================================================
-- DELIVERY ENVELOPE ASSEMBLY
-- Full envelope for a recipient device pull.
-- =========================================================

/*

PARAMETERS:

$1 = recipient_device_id

SELECT
    m.id            AS message_id,
    m.ciphertext,
    m.nonce,
    mq.associated_data,
    mq.msg_sequence,
    mq.expires_at

FROM message_queue mq

JOIN messages m
    ON m.id = mq.msg_id

WHERE mq.recipient_device_id = $1
  AND mq.delivery_state      = 'pending'
  AND m.deleted_at            IS NULL

ORDER BY mq.msg_sequence ASC;

Note: if m.deleted_at IS NOT NULL the message was retracted
by the sender before delivery; the server may return a
tombstone notification instead of the ciphertext.

*/

-- =========================================================
-- QUEUE LIMIT ENFORCEMENT
-- =========================================================

CREATE OR REPLACE FUNCTION enforce_queue_limit()
RETURNS TRIGGER AS $$
DECLARE
    max_messages INTEGER;
    current_count INTEGER;
BEGIN

    SELECT value::INTEGER
    INTO max_messages
    FROM system_config
    WHERE key = 'max_queue_messages_per_device';

    SELECT COUNT(*)
    INTO current_count
    FROM message_queue
    WHERE recipient_device_id = NEW.recipient_device_id
      AND delivery_state = 'pending';

    IF current_count >= max_messages THEN
        RAISE EXCEPTION
        'Recipient device queue limit exceeded';
    END IF;

    RETURN NEW;

END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_queue_limit
BEFORE INSERT ON message_queue
FOR EACH ROW
EXECUTE FUNCTION enforce_queue_limit();

-- =========================================================
-- EXPIRED MESSAGE CLEANUP
--
-- Ciphertext is now on messages, NOT on message_queue, so
-- there is nothing to wipe in the queue on ACK.
-- Queue rows are deleted outright once acknowledged or expired.
--
-- The wipe_ciphertext_on_ack trigger has been removed:
-- it was only needed when ciphertext lived on the queue row.
--
-- Soft-deleted messages are handled by a separate retention
-- job (see RETENTION note below); cleanup_expired_messages
-- only manages the queue.
--
-- PREVIOUS BUG (acknowledged-row leak) — FIXED:
--   Old logic:
--     DELETE FROM message_queue
--     WHERE delivery_state IN ('expired', 'acknowledged')
--       AND expires_at < NOW();    -- acknowledged rows with
--                                  -- future expires_at leaked.
--
--   Fix: acknowledged rows are hard-deleted unconditionally.
--   Expired rows keep expires_at < NOW() as a clock-skew guard.
-- =========================================================

CREATE OR REPLACE FUNCTION cleanup_expired_messages()
RETURNS void AS $$
BEGIN

    -- Mark pending rows past their TTL as expired.
    UPDATE message_queue
    SET delivery_state = 'expired'
    WHERE expires_at < NOW()
      AND delivery_state = 'pending';

    -- Hard-delete expired rows (TTL elapsed).
    DELETE FROM message_queue
    WHERE delivery_state = 'expired'
      AND expires_at < NOW();

    -- Hard-delete acknowledged rows unconditionally.
    -- Nothing sensitive remains in the queue row
    -- (ciphertext lives on messages, not here).
    DELETE FROM message_queue
    WHERE delivery_state = 'acknowledged';

END;
$$ LANGUAGE plpgsql;

-- =========================================================
-- SOFT-DELETED MESSAGE RETENTION
--
-- Separate job: hard-deletes messages rows where:
--   - deleted_at IS NOT NULL (sender deleted the message), AND
--   - All queue envelopes for this message are gone
--     (delivery to all devices is resolved — no in-flight ACK
--     window that might still need the ciphertext reference).
--
-- Grace period (e.g. 24 h) gives recipients time to receive
-- a "message retracted" tombstone before the row vanishes.
-- Adjust the interval to match your retention policy.
-- =========================================================

CREATE OR REPLACE FUNCTION cleanup_deleted_messages()
RETURNS void AS $$
BEGIN

    DELETE FROM messages m
    WHERE m.deleted_at IS NOT NULL
      AND m.deleted_at < NOW() - INTERVAL '24 hours'
      AND NOT EXISTS (
          SELECT 1
          FROM   message_queue mq
          WHERE  mq.msg_id = m.id
            AND  mq.delivery_state IN ('pending', 'delivered')
      );

END;
$$ LANGUAGE plpgsql;

-- =========================================================
-- PREKEY ROTATION DISCOVERY
-- =========================================================

CREATE OR REPLACE FUNCTION get_devices_needing_prekey_rotation()
RETURNS TABLE(device_id UUID) AS $$
DECLARE
    rotation_days INTEGER;
BEGIN

    SELECT value::INTEGER
    INTO rotation_days
    FROM system_config
    WHERE key = 'signed_prekey_rotation_days';

    RETURN QUERY

    SELECT d.id
    FROM devices d
    WHERE d.revoked = FALSE
      AND d.signed_prekey_created_at <
          NOW() - (rotation_days || ' days')::INTERVAL;

END;
$$ LANGUAGE plpgsql;

-- =========================================================
-- OPK LOW WATERMARK CHECK
-- =========================================================

CREATE OR REPLACE FUNCTION get_devices_low_opks()
RETURNS TABLE(device_id UUID) AS $$
DECLARE
    low_watermark INTEGER;
BEGIN

    SELECT value::INTEGER
    INTO low_watermark
    FROM system_config
    WHERE key = 'opk_low_watermark';

    RETURN QUERY

    SELECT d.id
    FROM devices d

    LEFT JOIN one_time_prekeys opk
        ON d.id = opk.device_id
       AND opk.used = FALSE

    WHERE d.revoked = FALSE

    GROUP BY d.id

    HAVING COUNT(opk.id) < low_watermark;

END;
$$ LANGUAGE plpgsql;

-- =========================================================
-- RECOMMENDED BLOCKCHAIN FLOW
--
-- Hashing uses keccak256 (NOT SHA-256) to match the
-- on-chain Solidity contract.
--
-- Merkle leaves are derived from messages (the permanent
-- record), not from message_queue (transient).  The queue
-- row may be gone by the time a verification request arrives;
-- the messages row persists.
-- =========================================================

/*

1. Select recent unanchored messages:

SELECT id, ciphertext, nonce, associated_data, created_at
FROM   messages
WHERE  deleted_at IS NULL
ORDER  BY created_at
LIMIT  1000;

2. Build Merkle tree from keccak256 leaf hashes:

keccak256(
    id ||
    ciphertext ||
    nonce ||
    associated_data ||
    created_at::text
)

   Use keccak256 — not SHA-256 — so leaf hashes and the
   Merkle root can be verified directly on-chain by the
   Solidity contract (Solidity's built-in keccak256()).

3. Submit Merkle root to the Sepolia smart contract.

4. Store root locally:

INSERT INTO merkle_roots (
    merkle_root,
    is_pending
)
VALUES (
    $1,   -- 0x-prefixed keccak256 hex string, CHAR(66)
    TRUE
);

5. Store the transaction hash once broadcast:

UPDATE merkle_roots
SET tx_hash = $tx_hash
WHERE id = $1;

6. When the blockchain confirms:

UPDATE merkle_roots
SET is_pending = FALSE
WHERE id = $1;

*/

-- =========================================================
-- SQL INJECTION PROTECTION
-- =========================================================

-- ALWAYS USE PARAMETERIZED QUERIES.

-- GOOD:
--   SELECT * FROM users WHERE username = $1;

-- BAD:
--   "SELECT * FROM users WHERE username = '" + username + "'"

-- =========================================================
-- IMPORTANT SECURITY NOTES
-- =========================================================

-- SAFE TO STORE (server-side):
--
-- - ciphertext (on messages; server cannot decrypt)
-- - nonce (on messages)
-- - associated_data (on messages and per-device in queue)
-- - public keys
-- - signed prekeys
-- - last resort OPK public key + signature
-- - timestamps
-- - keccak256 Merkle roots
-- - delivery state metadata
--
-- NEVER STORE:
--
-- - plaintext
-- - private keys
-- - root ratchet keys
-- - chain keys
-- - message keys
-- - decrypted attachments

-- =========================================================
-- AUTHENTICATION MODEL
-- =========================================================

-- INITIAL AUTHENTICATION:
--
-- username + password (Argon2id verified server-side)
--
-- DEVICE AUTHENTICATION:
--
-- challenge-response signatures using identity_signing_pub
--
-- NO:
--
-- - JWTs
-- - bearer tokens
-- - server-side sessions
