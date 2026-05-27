"""
routes/messages.py — Message send, fetch, delete, and acknowledge.

All routes require an authenticated session. The session middleware
must attach the following to the request before these handlers run:

    req.device_id  — UUID string of the authenticated device
    req.user_id    — UUID string of the owning user

Four endpoints:

    POST   /messages          — send a message (store + fanout to queue)
    GET    /messages          — pull pending delivery envelopes for this device
    DELETE /messages/<id>     — soft-delete a message (sender only)
    POST   /messages/<id>/ack — acknowledge delivery, hard-delete queue row
"""

from __future__ import annotations

import base64
import os
from datetime import datetime, timezone, timedelta

from pydantic import ValidationError

from api.models import MessagePayload
from api.database import query, with_transaction


# ── Constants ─────────────────────────────────────────────────────────────────

# Matches system_config row 'message_expiry_hours' = 168 (7 days).
# Read from system_config at startup in production; hardcoded here for clarity.
_MESSAGE_EXPIRY_HOURS = 168

# Maximum messages returned in a single pull (prevents oversized responses).
_PULL_LIMIT = 100


# ── Helpers ───────────────────────────────────────────────────────────────────

def _b64_decode(s: str) -> bytes:
    return base64.b64decode(s)


def _error(res, status: int, message: str):
    return res.status(status).json({"error": message})


# ── POST /messages ────────────────────────────────────────────────────────────

async def send_message(req, res):
    """
    Store a message and fan it out to every recipient device.

    Body (JSON) — matches MessagePayload in models.py:
        conversation_id   : str (UUID)
        recipient_device  : str (UUID)  — primary intended recipient
        ciphertext        : str (base64)
        nonce             : str (base64, 12 bytes)
        associated_data   : str (base64)
        x3dh_header       : object | null
            alice_idk_pub : str (base64, 32 bytes)
            alice_eph_pub : str (base64, 32 bytes)
            bob_opk_id    : str | null

    The server fans the message out to ALL active devices in the
    conversation except the sender's own device, not just
    recipient_device. recipient_device is recorded on the messages
    row for reference and OPK consumption.

    On success returns:
        { "message_id": "<uuid>" }
    """
    sender_device_id = req.device_id
    sender_user_id   = req.user_id

    # ── Validate payload ──────────────────────────────────────────────────────
    try:
        payload = MessagePayload.model_validate(req.body)
    except ValidationError as e:
        return _error(res, 400, e.errors()[0]["msg"])

    conversation_id = payload.conversation_id

    # ── Verify sender is a member of this conversation ────────────────────────
    membership = await query(
        """
        SELECT 1
        FROM   conversation_members cm
        JOIN   devices d ON d.user_id = cm.user_id
        WHERE  cm.conversation_id = $1
          AND  d.id               = $2
          AND  d.revoked          = FALSE
        """,
        [conversation_id, sender_device_id],
    )
    if not membership["rows"]:
        return _error(res, 403, "Not a member of this conversation")

    # ── Decode binary fields ──────────────────────────────────────────────────
    try:
        ciphertext      = _b64_decode(payload.ciphertext)
        nonce           = _b64_decode(payload.nonce)
        associated_data = _b64_decode(payload.associated_data)
    except Exception:
        return _error(res, 400, "Invalid base64 in payload")

    # ── Discover fanout recipients ────────────────────────────────────────────
    # All active devices in the conversation except the sender's own device.
    # Uses the FANOUT ENDPOINT DISCOVERY query from the schema.
    recipients = await query(
        """
        SELECT d.id AS device_id
        FROM   devices d
        JOIN   conversation_members cm ON d.user_id = cm.user_id
        WHERE  cm.conversation_id = $1
          AND  d.revoked          = FALSE
          AND  d.id              != $2
        """,
        [conversation_id, sender_device_id],
    )
    recipient_device_ids = [row["device_id"] for row in recipients["rows"]]

    if not recipient_device_ids:
        return _error(res, 400, "No recipients in conversation")

    # ── Mark OPK as used if X3DH header present ───────────────────────────────
    # The OPK is consumed exactly once — on the first message of a session.
    if payload.x3dh_header and payload.x3dh_header.bob_opk_id:
        opk_result = await query(
            """
            UPDATE one_time_prekeys
            SET    used    = TRUE,
                   used_at = NOW()
            WHERE  id        = $1
              AND  device_id = $2
              AND  used      = FALSE
            RETURNING id
            """,
            [payload.x3dh_header.bob_opk_id, payload.recipient_device],
        )
        # Non-fatal: OPK may already be consumed or last-resort was used.
        # The recipient will handle the key agreement failure themselves.

    expires_at = datetime.now(timezone.utc) + timedelta(hours=_MESSAGE_EXPIRY_HOURS)

    # ── Store message + queue rows in one transaction ─────────────────────────
    async def _fanout(client):
        return await _store_and_fanout(
            client,
            conversation_id  = conversation_id,
            sender_device_id = sender_device_id,
            ciphertext       = ciphertext,
            nonce            = nonce,
            associated_data  = associated_data,
            recipient_ids    = recipient_device_ids,
            expires_at       = expires_at,
        )

    try:
        message_id = await with_transaction(_fanout)
    except Exception as e:
        msg = str(e)
        if "queue limit exceeded" in msg.lower():
            return _error(res, 429, "Recipient device queue is full")
        raise

    return res.status(201).json({"message_id": str(message_id)})


async def _store_and_fanout(
    client,
    *,
    conversation_id: str,
    sender_device_id: str,
    ciphertext: bytes,
    nonce: bytes,
    associated_data: bytes,
    recipient_ids: list[str],
    expires_at: datetime,
) -> str:
    """
    Insert the messages row and one message_queue row per recipient device.
    Runs inside a transaction — either everything commits or nothing does.
    Returns the new message UUID.
    """
    # Insert permanent message record
    msg_result = await client.query(
        """
        INSERT INTO messages (
            conversation_id,
            sender_device_id,
            ciphertext,
            nonce,
            associated_data
        )
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
        """,
        [
            conversation_id,
            sender_device_id,
            ciphertext,
            nonce,
            associated_data,
        ],
    )
    message_id = msg_result["rows"][0]["id"]

    # Fan out: one queue row per recipient device.
    # msg_sequence uses the DB clock for ordering consistency.
    # The queue limit trigger fires here — raises if over 1000 pending.
    for device_id in recipient_ids:
        # Per-device associated_data could differ in a multi-device fanout.
        # For now we use the same associated_data as the message itself.
        # The recipient verifies this matches what they bound during encryption.
        seq_result = await client.query(
            """
            SELECT COALESCE(MAX(msg_sequence), 0) + 1 AS next_seq
            FROM   message_queue
            WHERE  recipient_device_id = $1
            """,
            [device_id],
        )
        next_seq = seq_result["rows"][0]["next_seq"]

        await client.query(
            """
            INSERT INTO message_queue (
                msg_id,
                recipient_device_id,
                associated_data,
                msg_sequence,
                expires_at
            )
            VALUES ($1, $2, $3, $4, $5)
            """,
            [
                message_id,
                device_id,
                associated_data,
                next_seq,
                expires_at,
            ],
        )

    return message_id


# ── GET /messages ─────────────────────────────────────────────────────────────

async def get_messages(req, res):
    """
    Pull pending delivery envelopes for the authenticated device.

    Uses the DELIVERY ENVELOPE ASSEMBLY query from the schema:
    joins message_queue with messages to return full envelopes.

    Returns up to _PULL_LIMIT messages ordered by msg_sequence ASC.

    Response:
        {
            "messages": [
                {
                    "message_id"     : "<uuid>",
                    "conversation_id": "<uuid>",
                    "sender_device_id": "<uuid>",
                    "ciphertext"     : "<base64>",
                    "nonce"          : "<base64>",
                    "associated_data": "<base64>",
                    "msg_sequence"   : 1,
                    "created_at"     : "<iso8601>",
                    "expires_at"     : "<iso8601>"
                },
                ...
            ]
        }

    Deleted messages (deleted_at IS NOT NULL) are returned as tombstones:
        {
            "message_id"  : "<uuid>",
            "deleted"     : true,
            "msg_sequence": N
        }
    so the recipient can update their local state.
    """
    device_id = req.device_id

    result = await query(
        """
        SELECT
            m.id                AS message_id,
            m.conversation_id,
            m.sender_device_id,
            m.ciphertext,
            m.nonce,
            mq.associated_data,
            mq.msg_sequence,
            m.created_at,
            mq.expires_at,
            m.deleted_at
        FROM   message_queue mq
        JOIN   messages m ON m.id = mq.msg_id
        WHERE  mq.recipient_device_id = $1
          AND  mq.delivery_state      = 'pending'
        ORDER  BY mq.msg_sequence ASC
        LIMIT  $2
        """,
        [device_id, _PULL_LIMIT],
    )

    messages = []
    queue_ids_to_mark = []

    for row in result["rows"]:
        if row["deleted_at"] is not None:
            # Tombstone — message was retracted before delivery
            messages.append({
                "message_id":   str(row["message_id"]),
                "deleted":      True,
                "msg_sequence": row["msg_sequence"],
            })
        else:
            messages.append({
                "message_id":      str(row["message_id"]),
                "conversation_id": str(row["conversation_id"]),
                "sender_device_id": str(row["sender_device_id"]),
                "ciphertext":      base64.b64encode(row["ciphertext"]).decode(),
                "nonce":           base64.b64encode(row["nonce"]).decode(),
                "associated_data": base64.b64encode(row["associated_data"]).decode(),
                "msg_sequence":    row["msg_sequence"],
                "created_at":      row["created_at"].isoformat(),
                "expires_at":      row["expires_at"].isoformat(),
            })
        queue_ids_to_mark.append(row["message_id"])

    # Mark fetched rows as delivered (not yet acknowledged)
    if queue_ids_to_mark:
        await query(
            """
            UPDATE message_queue
            SET    delivery_state = 'delivered',
                   delivered_at  = NOW()
            WHERE  recipient_device_id = $1
              AND  msg_id = ANY($2::uuid[])
              AND  delivery_state = 'pending'
            """,
            [device_id, queue_ids_to_mark],
        )

    return res.json({"messages": messages})


# ── POST /messages/<id>/ack ───────────────────────────────────────────────────

async def ack_message(req, res):
    """
    Acknowledge delivery of a message.

    Marks the queue row as acknowledged. The cleanup job hard-deletes
    acknowledged rows (ciphertext stays on messages, nothing sensitive
    is lost — see schema rationale).

    URL param: message_id (UUID)

    Response: { "acknowledged": true }
    """
    device_id  = req.device_id
    message_id = req.params.get("id")

    if not message_id:
        return _error(res, 400, "Missing message_id")

    result = await query(
        """
        UPDATE message_queue
        SET    delivery_state    = 'acknowledged',
               acknowledged_at  = NOW()
        WHERE  msg_id              = $1
          AND  recipient_device_id = $2
          AND  delivery_state      = 'delivered'
        RETURNING id
        """,
        [message_id, device_id],
    )

    if not result["rows"]:
        # Either already acked, never delivered to this device, or wrong device.
        # Uniform response — don't distinguish (oracle prevention).
        return _error(res, 404, "Message not found")

    return res.json({"acknowledged": True})


# ── DELETE /messages/<id> ─────────────────────────────────────────────────────

async def delete_message(req, res):
    """
    Soft-delete a message. Sender only.

    Uses the ACCESS CONTROL pattern from the schema:
    verifies sender_device_id belongs to the authenticated user
    before setting deleted_at.

    Only the sender may delete. Recipients cannot.
    Idempotent: deleting an already-deleted message is a no-op (200).

    URL param: id (UUID)

    Response: { "deleted": true }
    """
    device_id = req.device_id
    user_id   = req.user_id
    message_id = req.params.get("id")

    if not message_id:
        return _error(res, 400, "Missing message_id")

    result = await query(
        """
        UPDATE messages
        SET    deleted_at           = NOW(),
               deleted_by_device_id = $1
        WHERE  id                   = $2
          AND  sender_device_id IN (
                   SELECT id
                   FROM   devices
                   WHERE  user_id = $3
               )
          AND  deleted_at IS NULL
        RETURNING id
        """,
        [device_id, message_id, user_id],
    )

    if not result["rows"]:
        # Either already deleted (idempotent → 200) or not the sender (403).
        # Check which to give a useful response without leaking existence.
        check = await query(
            """
            SELECT sender_device_id, deleted_at
            FROM   messages
            WHERE  id = $1
            """,
            [message_id],
        )

        if not check["rows"]:
            return _error(res, 404, "Message not found")

        row = check["rows"][0]

        if row["deleted_at"] is not None:
            # Already deleted — idempotent success
            return res.json({"deleted": True})

        # Message exists but sender_device_id doesn't belong to this user
        return _error(res, 403, "Not authorised to delete this message")

    return res.json({"deleted": True})
