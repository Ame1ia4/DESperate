-- =========================================================
-- 003_device_srp_session.sql
-- Track SRP session lifetime on the device.
--
-- After a successful SRP handshake the server knows the
-- device has authenticated but has nowhere to record when
-- that happened or when the session expires. These two
-- columns provide that anchor so protected endpoints can
-- enforce session freshness without issuing tokens.
--
-- srp_verified_at  — timestamp of the last successful
--                    /auth/verify for this device.
-- srp_expires_at   — when the session is considered stale
--                    and the device must re-authenticate.
--
-- Both are nullable: NULL means the device has never
-- completed an SRP handshake and must authenticate before
-- accessing protected resources.
-- =========================================================

-- UP:

ALTER TABLE devices
    ADD COLUMN srp_verified_at TIMESTAMPTZ,
    ADD COLUMN srp_expires_at  TIMESTAMPTZ;

-- DOWN:

ALTER TABLE devices
    DROP COLUMN IF EXISTS srp_verified_at,
    DROP COLUMN IF EXISTS srp_expires_at;
