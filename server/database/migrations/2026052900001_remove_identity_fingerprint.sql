-- Remove identity_fingerprint column from devices.
-- The fingerprint is derived from public key material and should
-- be computed client-side rather than stored server-side.

DROP INDEX IF EXISTS public.idx_device_fingerprint;

ALTER TABLE devices DROP COLUMN identity_fingerprint;
