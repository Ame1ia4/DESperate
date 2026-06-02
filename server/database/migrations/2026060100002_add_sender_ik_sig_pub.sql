-- Migration: Add sender_ik_sig_pub column to messages table
-- Purpose: Store the sender's signed identity key public key for PQXDH verification
-- 
-- The Python crypto service returns sender_ik_sig_pub when encrypting a message.
-- Recipients need this to verify message signatures (hybrid Ed25519/ML-DSA-87 signatures).
-- Previously, it was discarded by the server; now we store it so recipients can retrieve it.

ALTER TABLE messages
  ADD COLUMN sender_ik_sig_pub TEXT;

-- Create index for potential future lookups by sender's sig pub
CREATE INDEX idx_messages_sender_ik_sig_pub
  ON messages(sender_ik_sig_pub)
  WHERE sender_ik_sig_pub IS NOT NULL;
