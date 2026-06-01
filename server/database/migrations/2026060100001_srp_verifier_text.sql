-- 2026060100001_srp_verifier_text.sql
-- Widen srp_salt and srp_verifier from VARCHAR to TEXT.
--
-- Root cause: schema.sql had srp_verifier VARCHAR(512) and srp_salt VARCHAR(64).
-- For the 3072-bit SRP group (RFC 5054 §A.3) the verifier v = g^x mod N is at
-- most 384 bytes, stored as 768 hex chars.  VARCHAR(512) is too narrow →
-- PostgreSQL throws "value too long" → POST /auth/register returns 500.
--
-- TEXT has no length limit and accepts the existing data unchanged.
-- This migration is idempotent — running it on a fresh schema is harmless.

ALTER TABLE users
    ALTER COLUMN srp_salt     TYPE TEXT,
    ALTER COLUMN srp_verifier TYPE TEXT;
