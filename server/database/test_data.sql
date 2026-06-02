-- Test data for local development
-- Run with: psql -U des_user -d desperate_db -f server/database/test_data.sql

INSERT INTO users (id, username, srp_salt, srp_verifier) VALUES
  ('aaaaaaaa-0000-0000-0000-000000000001', 'alice', 'deadsalt01', 'deadverifier01'),
  ('aaaaaaaa-0000-0000-0000-000000000002', 'bob',   'deadsalt02', 'deadverifier02');

INSERT INTO devices (id, user_id, idk_classical_pub, identity_signing_pub, signed_prekey_pub, signed_prekey_signature) VALUES
  ('bbbbbbbb-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', decode('aa01aa01aa01aa01aa01aa01aa01aa01aa01aa01aa01aa01aa01aa01aa01aa01', 'hex'), decode('bb01bb01bb01bb01bb01bb01bb01bb01bb01bb01bb01bb01bb01bb01bb01bb01', 'hex'), decode('cc01cc01cc01cc01cc01cc01cc01cc01cc01cc01cc01cc01cc01cc01cc01cc01', 'hex'), decode('dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01dd01', 'hex')),
  ('bbbbbbbb-0000-0000-0000-000000000002', 'aaaaaaaa-0000-0000-0000-000000000002', decode('aa02aa02aa02aa02aa02aa02aa02aa02aa02aa02aa02aa02aa02aa02aa02aa02', 'hex'), decode('bb02bb02bb02bb02bb02bb02bb02bb02bb02bb02bb02bb02bb02bb02bb02bb02', 'hex'), decode('cc02cc02cc02cc02cc02cc02cc02cc02cc02cc02cc02cc02cc02cc02cc02cc02', 'hex'), decode('dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02dd02', 'hex'));

INSERT INTO conversations (id) VALUES
  ('cccccccc-0000-0000-0000-000000000001');

INSERT INTO conversation_members (conversation_id, user_id) VALUES
  ('cccccccc-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001'),
  ('cccccccc-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000002');

INSERT INTO messages (id, conversation_id, sender_device_id, ciphertext, nonce, associated_data) VALUES
  ('dddddddd-0000-0000-0000-000000000001', 'cccccccc-0000-0000-0000-000000000001', 'bbbbbbbb-0000-0000-0000-000000000001', decode('deadbeef01', 'hex'), decode('010203040506070809101112', 'hex'), decode('cccccccc00000000000000000000000000000001', 'hex')),
  ('dddddddd-0000-0000-0000-000000000002', 'cccccccc-0000-0000-0000-000000000001', 'bbbbbbbb-0000-0000-0000-000000000002', decode('deadbeef02', 'hex'), decode('020304050607080910111213', 'hex'), decode('cccccccc00000000000000000000000000000001', 'hex')),
  ('dddddddd-0000-0000-0000-000000000003', 'cccccccc-0000-0000-0000-000000000001', 'bbbbbbbb-0000-0000-0000-000000000001', decode('deadbeef03', 'hex'), decode('030405060708091011121314', 'hex'), decode('cccccccc00000000000000000000000000000001', 'hex')),
  ('dddddddd-0000-0000-0000-000000000004', 'cccccccc-0000-0000-0000-000000000001', 'bbbbbbbb-0000-0000-0000-000000000002', decode('deadbeef04', 'hex'), decode('040506070809101112131415', 'hex'), decode('cccccccc00000000000000000000000000000001', 'hex'));

INSERT INTO merkle_leaves (leaf_hash, msg_id, state) VALUES
  ('0xdeadbeef01deadbeef01deadbeef01deadbeef01deadbeef01deadbeef010001', 'dddddddd-0000-0000-0000-000000000001', 'pending'),
  ('0xdeadbeef02deadbeef02deadbeef02deadbeef02deadbeef02deadbeef020002', 'dddddddd-0000-0000-0000-000000000002', 'pending'),
  ('0xdeadbeef03deadbeef03deadbeef03deadbeef03deadbeef03deadbeef030003', 'dddddddd-0000-0000-0000-000000000003', 'pending'),
  ('0xdeadbeef04deadbeef04deadbeef04deadbeef04deadbeef04deadbeef040004', 'dddddddd-0000-0000-0000-000000000004', 'pending');
