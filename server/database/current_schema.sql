--
-- PostgreSQL database dump
--

\restrict FC8SmpsRMf18aAeQEY9jib4eGteaXSx9QimdcN0xbdVcXwbcQdm2Q0pQRalNbHp

-- Dumped from database version 16.14 (Ubuntu 16.14-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.14 (Ubuntu 16.14-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: cleanup_deleted_messages(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.cleanup_deleted_messages() RETURNS void
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.cleanup_deleted_messages() OWNER TO postgres;

--
-- Name: cleanup_expired_messages(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.cleanup_expired_messages() RETURNS void
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.cleanup_expired_messages() OWNER TO postgres;

--
-- Name: cleanup_srp_challenges(); Type: FUNCTION; Schema: public; Owner: desperate
--

CREATE FUNCTION public.cleanup_srp_challenges() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM srp_challenges WHERE expires_at < NOW();
END;
$$;


ALTER FUNCTION public.cleanup_srp_challenges() OWNER TO desperate;

--
-- Name: enforce_queue_limit(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.enforce_queue_limit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.enforce_queue_limit() OWNER TO postgres;

--
-- Name: get_devices_low_opks(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_devices_low_opks() RETURNS TABLE(device_id uuid)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.get_devices_low_opks() OWNER TO postgres;

--
-- Name: get_devices_needing_prekey_rotation(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.get_devices_needing_prekey_rotation() RETURNS TABLE(device_id uuid)
    LANGUAGE plpgsql
    AS $$
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
$$;


ALTER FUNCTION public.get_devices_needing_prekey_rotation() OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: conversation_members; Type: TABLE; Schema: public; Owner: desperate
--

CREATE TABLE public.conversation_members (
    conversation_id uuid NOT NULL,
    user_id uuid NOT NULL,
    joined_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.conversation_members OWNER TO desperate;

--
-- Name: conversations; Type: TABLE; Schema: public; Owner: desperate
--

CREATE TABLE public.conversations (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.conversations OWNER TO desperate;

--
-- Name: devices; Type: TABLE; Schema: public; Owner: desperate
--

CREATE TABLE public.devices (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid NOT NULL,
    device_name character varying(100),
    idk_classical_pub bytea NOT NULL,
    idk_pq_pub bytea,
    identity_signing_pub bytea NOT NULL,
    identity_fingerprint character varying(128) NOT NULL,
    signed_prekey_pub bytea NOT NULL,
    signed_prekey_signature bytea NOT NULL,
    signed_prekey_created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_resort_opk_pub bytea,
    last_resort_opk_signature bytea,
    last_resort_opk_created_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_seen timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    revoked boolean DEFAULT false NOT NULL,
    srp_verified_at timestamp with time zone,
    srp_expires_at timestamp with time zone
);


ALTER TABLE public.devices OWNER TO desperate;

--
-- Name: merkle_roots; Type: TABLE; Schema: public; Owner: desperate
--

CREATE TABLE public.merkle_roots (
    id integer NOT NULL,
    merkle_root character(66) NOT NULL,
    tx_hash character(66),
    broadcast_to_chain boolean DEFAULT false NOT NULL
);


ALTER TABLE public.merkle_roots OWNER TO desperate;

--
-- Name: merkle_roots_id_seq; Type: SEQUENCE; Schema: public; Owner: desperate
--

CREATE SEQUENCE public.merkle_roots_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.merkle_roots_id_seq OWNER TO desperate;

--
-- Name: merkle_roots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: desperate
--

ALTER SEQUENCE public.merkle_roots_id_seq OWNED BY public.merkle_roots.id;


--
-- Name: message_queue; Type: TABLE; Schema: public; Owner: desperate
--

CREATE TABLE public.message_queue (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    msg_id uuid NOT NULL,
    recipient_device_id uuid NOT NULL,
    associated_data bytea NOT NULL,
    msg_sequence bigint NOT NULL,
    queued_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    delivered_at timestamp with time zone,
    acknowledged_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    delivery_state character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    CONSTRAINT message_queue_delivery_state_check CHECK (((delivery_state)::text = ANY ((ARRAY['pending'::character varying, 'delivered'::character varying, 'acknowledged'::character varying, 'expired'::character varying, 'failed'::character varying])::text[])))
);


ALTER TABLE public.message_queue OWNER TO desperate;

--
-- Name: messages; Type: TABLE; Schema: public; Owner: desperate
--

CREATE TABLE public.messages (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    conversation_id uuid NOT NULL,
    sender_device_id uuid NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    associated_data bytea NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at timestamp with time zone,
    deleted_by_device_id uuid,
    CONSTRAINT messages_check CHECK ((((deleted_at IS NULL) AND (deleted_by_device_id IS NULL)) OR ((deleted_at IS NOT NULL) AND (deleted_by_device_id IS NOT NULL)))),
    CONSTRAINT messages_ciphertext_check CHECK ((octet_length(ciphertext) <= 65536)),
    CONSTRAINT messages_nonce_check CHECK ((octet_length(nonce) = 12))
);


ALTER TABLE public.messages OWNER TO desperate;

--
-- Name: one_time_prekeys; Type: TABLE; Schema: public; Owner: desperate
--

CREATE TABLE public.one_time_prekeys (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    device_id uuid NOT NULL,
    opk_pub bytea NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    used boolean DEFAULT false NOT NULL,
    used_at timestamp with time zone
);


ALTER TABLE public.one_time_prekeys OWNER TO desperate;

--
-- Name: pgmigrations; Type: TABLE; Schema: public; Owner: desperate
--

CREATE TABLE public.pgmigrations (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    run_on timestamp without time zone NOT NULL
);


ALTER TABLE public.pgmigrations OWNER TO desperate;

--
-- Name: pgmigrations_id_seq; Type: SEQUENCE; Schema: public; Owner: desperate
--

CREATE SEQUENCE public.pgmigrations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.pgmigrations_id_seq OWNER TO desperate;

--
-- Name: pgmigrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: desperate
--

ALTER SEQUENCE public.pgmigrations_id_seq OWNED BY public.pgmigrations.id;


--
-- Name: srp_challenges; Type: TABLE; Schema: public; Owner: desperate
--

CREATE TABLE public.srp_challenges (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid NOT NULL,
    srp_server_secret bytea NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP + '00:05:00'::interval) NOT NULL
);


ALTER TABLE public.srp_challenges OWNER TO desperate;

--
-- Name: system_config; Type: TABLE; Schema: public; Owner: desperate
--

CREATE TABLE public.system_config (
    key text NOT NULL,
    value text NOT NULL
);


ALTER TABLE public.system_config OWNER TO desperate;

--
-- Name: users; Type: TABLE; Schema: public; Owner: desperate
--

CREATE TABLE public.users (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    username character varying(50) NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_seen timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    account_status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    srp_salt bytea DEFAULT '\x'::bytea NOT NULL,
    srp_verifier bytea DEFAULT '\x'::bytea NOT NULL,
    CONSTRAINT users_account_status_check CHECK (((account_status)::text = ANY ((ARRAY['active'::character varying, 'disabled'::character varying, 'locked'::character varying])::text[])))
);


ALTER TABLE public.users OWNER TO desperate;

--
-- Name: COLUMN users.srp_salt; Type: COMMENT; Schema: public; Owner: desperate
--

COMMENT ON COLUMN public.users.srp_salt IS '32-byte random salt stored as binary. Sent to client in round 1 so it can derive x via Argon2id.';


--
-- Name: COLUMN users.srp_verifier; Type: COMMENT; Schema: public; Owner: desperate
--

COMMENT ON COLUMN public.users.srp_verifier IS 'Binary SRP-6a verifier v = g^x mod N (RFC 5054, 2048-bit group, SHA-256, x derived via Argon2id RFC 9106). Never transmit to the client.';


--
-- Name: merkle_roots id; Type: DEFAULT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.merkle_roots ALTER COLUMN id SET DEFAULT nextval('public.merkle_roots_id_seq'::regclass);


--
-- Name: pgmigrations id; Type: DEFAULT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.pgmigrations ALTER COLUMN id SET DEFAULT nextval('public.pgmigrations_id_seq'::regclass);


--
-- Name: conversation_members conversation_members_pkey; Type: CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.conversation_members
    ADD CONSTRAINT conversation_members_pkey PRIMARY KEY (conversation_id, user_id);


--
-- Name: conversations conversations_pkey; Type: CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.conversations
    ADD CONSTRAINT conversations_pkey PRIMARY KEY (id);


--
-- Name: devices devices_pkey; Type: CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (id);


--
-- Name: merkle_roots merkle_roots_merkle_root_key; Type: CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.merkle_roots
    ADD CONSTRAINT merkle_roots_merkle_root_key UNIQUE (merkle_root);


--
-- Name: merkle_roots merkle_roots_pkey; Type: CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.merkle_roots
    ADD CONSTRAINT merkle_roots_pkey PRIMARY KEY (id);


--
-- Name: merkle_roots merkle_roots_tx_hash_key; Type: CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.merkle_roots
    ADD CONSTRAINT merkle_roots_tx_hash_key UNIQUE (tx_hash);


--
-- Name: message_queue message_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.message_queue
    ADD CONSTRAINT message_queue_pkey PRIMARY KEY (id);


--
-- Name: messages messages_pkey; Type: CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id);


--
-- Name: one_time_prekeys one_time_prekeys_pkey; Type: CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.one_time_prekeys
    ADD CONSTRAINT one_time_prekeys_pkey PRIMARY KEY (id);


--
-- Name: pgmigrations pgmigrations_pkey; Type: CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.pgmigrations
    ADD CONSTRAINT pgmigrations_pkey PRIMARY KEY (id);


--
-- Name: srp_challenges srp_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.srp_challenges
    ADD CONSTRAINT srp_challenges_pkey PRIMARY KEY (id);


--
-- Name: system_config system_config_pkey; Type: CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.system_config
    ADD CONSTRAINT system_config_pkey PRIMARY KEY (key);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: idx_conversation_members_user; Type: INDEX; Schema: public; Owner: desperate
--

CREATE INDEX idx_conversation_members_user ON public.conversation_members USING btree (user_id);


--
-- Name: idx_device_fingerprint; Type: INDEX; Schema: public; Owner: desperate
--

CREATE UNIQUE INDEX idx_device_fingerprint ON public.devices USING btree (identity_fingerprint);


--
-- Name: idx_devices_active; Type: INDEX; Schema: public; Owner: desperate
--

CREATE INDEX idx_devices_active ON public.devices USING btree (id) WHERE (revoked = false);


--
-- Name: idx_devices_user; Type: INDEX; Schema: public; Owner: desperate
--

CREATE INDEX idx_devices_user ON public.devices USING btree (user_id) WHERE (revoked = false);


--
-- Name: idx_merkle_roots_tx; Type: INDEX; Schema: public; Owner: desperate
--

CREATE INDEX idx_merkle_roots_tx ON public.merkle_roots USING btree (tx_hash) WHERE (tx_hash IS NOT NULL);


--
-- Name: idx_messages_conversation; Type: INDEX; Schema: public; Owner: desperate
--

CREATE INDEX idx_messages_conversation ON public.messages USING btree (conversation_id, created_at) WHERE (deleted_at IS NULL);


--
-- Name: idx_messages_deleted; Type: INDEX; Schema: public; Owner: desperate
--

CREATE INDEX idx_messages_deleted ON public.messages USING btree (deleted_at) WHERE (deleted_at IS NOT NULL);


--
-- Name: idx_opk_lookup; Type: INDEX; Schema: public; Owner: desperate
--

CREATE INDEX idx_opk_lookup ON public.one_time_prekeys USING btree (device_id) WHERE (used = false);


--
-- Name: idx_queue_delivery; Type: INDEX; Schema: public; Owner: desperate
--

CREATE INDEX idx_queue_delivery ON public.message_queue USING btree (recipient_device_id, delivery_state, queued_at);


--
-- Name: idx_queue_expiry; Type: INDEX; Schema: public; Owner: desperate
--

CREATE INDEX idx_queue_expiry ON public.message_queue USING btree (expires_at);


--
-- Name: idx_queue_message; Type: INDEX; Schema: public; Owner: desperate
--

CREATE INDEX idx_queue_message ON public.message_queue USING btree (msg_id);


--
-- Name: idx_queue_sequence_unique; Type: INDEX; Schema: public; Owner: desperate
--

CREATE UNIQUE INDEX idx_queue_sequence_unique ON public.message_queue USING btree (recipient_device_id, msg_sequence);


--
-- Name: idx_srp_challenges_user; Type: INDEX; Schema: public; Owner: desperate
--

CREATE INDEX idx_srp_challenges_user ON public.srp_challenges USING btree (user_id, expires_at);


--
-- Name: idx_users_username; Type: INDEX; Schema: public; Owner: desperate
--

CREATE INDEX idx_users_username ON public.users USING btree (username);


--
-- Name: message_queue trg_queue_limit; Type: TRIGGER; Schema: public; Owner: desperate
--

CREATE TRIGGER trg_queue_limit BEFORE INSERT ON public.message_queue FOR EACH ROW EXECUTE FUNCTION public.enforce_queue_limit();


--
-- Name: conversation_members conversation_members_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.conversation_members
    ADD CONSTRAINT conversation_members_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.conversations(id) ON DELETE CASCADE;


--
-- Name: conversation_members conversation_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.conversation_members
    ADD CONSTRAINT conversation_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: devices devices_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: message_queue message_queue_msg_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.message_queue
    ADD CONSTRAINT message_queue_msg_id_fkey FOREIGN KEY (msg_id) REFERENCES public.messages(id) ON DELETE CASCADE;


--
-- Name: message_queue message_queue_recipient_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.message_queue
    ADD CONSTRAINT message_queue_recipient_device_id_fkey FOREIGN KEY (recipient_device_id) REFERENCES public.devices(id) ON DELETE CASCADE;


--
-- Name: messages messages_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.conversations(id) ON DELETE CASCADE;


--
-- Name: messages messages_deleted_by_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_deleted_by_device_id_fkey FOREIGN KEY (deleted_by_device_id) REFERENCES public.devices(id);


--
-- Name: messages messages_sender_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_sender_device_id_fkey FOREIGN KEY (sender_device_id) REFERENCES public.devices(id);


--
-- Name: one_time_prekeys one_time_prekeys_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.one_time_prekeys
    ADD CONSTRAINT one_time_prekeys_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;


--
-- Name: srp_challenges srp_challenges_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: desperate
--

ALTER TABLE ONLY public.srp_challenges
    ADD CONSTRAINT srp_challenges_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict FC8SmpsRMf18aAeQEY9jib4eGteaXSx9QimdcN0xbdVcXwbcQdm2Q0pQRalNbHp

