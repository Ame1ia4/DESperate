-- 2026060200001_srp_challenges_flow.sql
-- Add a `flow` discriminator to srp_challenges so the login handshake and
-- the password-change handshake can hold active challenges for the same device
-- simultaneously without clobbering each other.
--
-- Old schema: PRIMARY KEY (device_id) — only one challenge per device.
-- New schema: PRIMARY KEY (device_id, flow) — one challenge per device per flow.
--
-- Safe to run on a fresh schema.sql database (IF NOT EXISTS / IF EXISTS guards).

-- 1. Add the column (default 'login' back-fills any live rows).
ALTER TABLE srp_challenges
    ADD COLUMN IF NOT EXISTS flow VARCHAR(20) NOT NULL DEFAULT 'login';

-- 2. Add the check constraint (idempotent name prevents duplicate on re-run).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'srp_challenges_flow_check'
    ) THEN
        ALTER TABLE srp_challenges
            ADD CONSTRAINT srp_challenges_flow_check
                CHECK (flow IN ('login', 'password_change'));
    END IF;
END;
$$;

-- 3. Swap the primary key from (device_id) to (device_id, flow).
ALTER TABLE srp_challenges DROP CONSTRAINT IF EXISTS srp_challenges_pkey;
ALTER TABLE srp_challenges ADD PRIMARY KEY (device_id, flow);
