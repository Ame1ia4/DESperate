#include "MessageController.h"

#include <QDateTime>
#include <QJsonArray>
#include <QUuid>

#include "ConversationController.h"

#include "src/models/MessageModel.h"
#include "src/services/ApiClient.h"
#include "src/services/CryptoServiceClient.h"
#include "src/storage/LocalMessageStore.h"
#include "src/storage/TrustStore.h"
#include "src/types/Types.h"

MessageController::MessageController(
    ApiClient* api,
    CryptoServiceClient* crypto,
    LocalMessageStore* store,
    MessageModel* model,
    ConversationController* conversations,
    TrustStore* trust,
    SessionStore* sessions,
    QObject* parent)
    : QObject(parent)
    , m_api(api)
    , m_crypto(crypto)
    , m_store(store)
    , m_model(model)
    , m_conversations(conversations)
    , m_trust(trust)
    , m_sessions(sessions)
{
    connect(
        m_crypto,
        &CryptoServiceClient::encryptCompleted,
        this,
        &MessageController
        ::handleEncryptCompleted);

    connect(
        m_crypto,
        &CryptoServiceClient::encryptFailed,
        this,
        &MessageController
        ::handleEncryptFailed);

    connect(
        m_crypto,
        &CryptoServiceClient::decryptCompleted,
        this,
        &MessageController
        ::handleDecryptCompleted);

    connect(
        m_crypto,
        &CryptoServiceClient::decryptFailed,
        this,
        &MessageController
        ::handleDecryptFailed);
}

void MessageController::deleteMessage(const QString& messageId)
{
    m_api->deleteMessage(messageId);
}

void MessageController::revokeMessage(const QString& messageId, const QString& recipientDeviceId)
{
    m_api->revokeMessage(messageId, recipientDeviceId);
}

void MessageController::sendText(
    const QString& conversationId,
    const QString& text)
{
    const QString trimmed = text.trimmed();

    if (trimmed.isEmpty()) {
        return;
    }

    const QString deviceId =
        m_conversations->deviceIdForConversation(
            conversationId);

    sendMessage(
        conversationId,
        deviceId,
        trimmed.toUtf8());
}

void MessageController::sendMessage(
    QString conversationId,
    QString recipientDeviceId,
    QByteArray plaintext)
{
    if (conversationId.isEmpty()) {

        emit messageSendFailed(
            "Conversation ID missing.");

        return;
    }

    if (recipientDeviceId.isEmpty()) {

        emit messageSendFailed(
            "Recipient device missing.");

        return;
    }

    if (plaintext.isEmpty()) {

        emit messageSendFailed(
            "Message payload empty.");

        return;
    }

    const QString requestId =
        QUuid::createUuid().toString();

    PendingMessage pending;

    pending.requestId =
        requestId;

    pending.conversationId =
        conversationId;

    pending.recipientDeviceId =
        recipientDeviceId;

    pending.plaintext =
        plaintext;

    m_pendingMessages.insert(
        requestId,
        pending);

    m_crypto->encryptMessageAsync(
        requestId,
        plaintext,
        recipientDeviceId,
        conversationId);
}

void MessageController::handleEncryptCompleted(
    QString requestId,
    QJsonObject envelope)
{
    if (!m_pendingMessages.contains(
            requestId)) {

        return;
    }

    const PendingMessage pending =
        m_pendingMessages.take(
            requestId);

    // Inject fields the server requires that the crypto service doesn't produce.
    QJsonObject fullEnvelope = envelope;
    fullEnvelope["conversation_id"] = pending.conversationId;

    qDebug() << "[SEND] encryped OK, posting to server | conv:" << pending.conversationId
             << "| ciphertext len:" << envelope["ciphertext"].toString().length();

    m_store->storeOutgoingMessage(fullEnvelope);
    m_api->sendMessage(fullEnvelope);

    // Optimistic UI update.
    DecryptedMessage message;

    message.id =
        envelope.value("id").toString(
            QUuid::createUuid()
                .toString());

    message.conversationId =
        pending.conversationId;

    message.senderDeviceId =
        "self";

    message.timestamp =
        QDateTime::currentDateTimeUtc();

    message.plaintext =
        QString::fromUtf8(
            pending.plaintext);

    // C1 fix: outgoing messages are only Verified if TrustStore confirms
    // the recipient's identity key is pinned and matches. Previously this
    // was hardcoded to Verified, meaning the UI always showed a green tick
    // regardless of whether identity verification had ever run.
    {
        const QString participant =
            m_conversations->participantForConversation(
                pending.conversationId);
        message.verificationState =
            (!participant.isEmpty() && m_trust->isVerified(participant))
                ? VerificationState::Verified
                : VerificationState::Failed;
    }

    m_conversations
        ->appendLocalMessage(message);

    m_store->storeDecryptedMessage(message);

    emit messageSent();
}

void MessageController::handleEncryptFailed(
    QString requestId,
    QString reason)
{
    m_pendingMessages.remove(
        requestId);

    emit messageSendFailed(
        reason.isEmpty()
            ? "Encryption failed."
            : reason);
}

void MessageController::receiveEnvelope(
    QJsonObject envelope)
{
    const QString requestId =
        QUuid::createUuid().toString();

    m_pendingDecryptions.insert(
        requestId,
        envelope);

    m_crypto->decryptMessageAsync(
        requestId,
        envelope);
}

void MessageController::handleDecryptCompleted(
    QString requestId,
    QString plaintext)
{
    if (!m_pendingDecryptions.contains(
            requestId)) {

        return;
    }

    const QJsonObject envelope =
        m_pendingDecryptions.take(
            requestId);

    const auto senderTimestamp =
        QDateTime::fromString(
            envelope.value(
                        "created_at")
                .toString(),
            Qt::ISODateWithMs);

    DecryptedMessage message;

    message.id =
        envelope.value("id")
            .toString();

    message.conversationId =
        envelope.value(
                    "conversation_id")
            .toString();

    message.senderDeviceId =
        envelope.value(
                    "sender_device_id")
            .toString();

    message.timestamp =
        senderTimestamp.isValid()
            ? senderTimestamp
            : QDateTime
            ::currentDateTimeUtc();

    message.plaintext =
        plaintext;

    // C1 fix: incoming messages are only Verified if TrustStore confirms
    // the sender's identity is pinned and matches. Previously hardcoded
    // to Verified — the UI reported every message as authenticated even
    // when no identity check had ever been performed.
    {
        const QString conversationId =
            envelope.value("conversation_id").toString();
        const QString participant =
            m_conversations->participantForConversation(conversationId);
        message.verificationState =
            (!participant.isEmpty() && m_trust->isVerified(participant))
                ? VerificationState::Verified
                : VerificationState::Failed;
    }

    m_store->storeDecryptedMessage(
        message);

    m_conversations
        ->appendLocalMessage(message);

    m_api->acknowledgeMessage(
        message.id,
        envelope.value(
                    "recipient_device_id")
            .toString());

    emit messageReceived();
}

void MessageController::handleDecryptFailed(
    QString requestId,
    QString reason)
{
    const QJsonObject envelope =
        m_pendingDecryptions.take(
            requestId);

    // Acknowledge undecryptable messages so they clear from the server queue.
    // Without this they re-appear on every poll, looping forever.
    if (!envelope.isEmpty()) {
        const QString messageId =
            envelope.value("id").toString();
        const QString recipientDeviceId =
            envelope.value("recipient_device_id").toString();
        if (!messageId.isEmpty() &&
            !recipientDeviceId.isEmpty()) {
            m_api->acknowledgeMessage(
                messageId,
                recipientDeviceId);
        }

        // The sender's session is stale — their first message (with the
        // initiation_bundle) never reached us. Re-initiate, but only if we
        // have no session of our own: if we already have a pending or active
        // session we are the initiator and re-initiating would create a
        // competing session that neither side can decrypt.
        if (reason.contains(QStringLiteral("no initiation_bundle"))) {
            const QString conversationId =
                envelope.value(QStringLiteral("conversation_id")).toString();
            if (!conversationId.isEmpty() &&
                !m_crypto->hasSession(conversationId))
                m_conversations->reinitiateSession(conversationId);
        }
    }

    emit messageReceiveFailed(
        reason.isEmpty()
            ? "Decryption failed."
            : reason);
}

void MessageController::pullAndProcessMessages(
    QString deviceId)
{
    connect(
        m_api,
        &ApiClient::pullMessagesSucceeded,
        this,
        [this](const QJsonArray& envelopes) {

            for (const auto& value :
                 envelopes) {

                const auto envelope =
                    value.toObject();

                if (!envelope.isEmpty()) {
                    receiveEnvelope(
                        envelope);
                }
            }
        },
        Qt::SingleShotConnection);

    connect(
        m_api,
        &ApiClient::pullMessagesFailed,
        this,
        [this]() {

            emit messageReceiveFailed(
                "Failed to pull messages.");
        },
        Qt::SingleShotConnection);

    m_api->pullMessages(deviceId);
}

void MessageController::fetchConversationHistory(const QString& conversationId)
{
    connect(
        m_api,
        &ApiClient::fetchConversationMessagesSucceeded,
        this,
        [this](const QJsonArray& messages) {
            for (const auto& value : messages) {
                const auto envelope = value.toObject();
                if (!envelope.isEmpty()) {
                    receiveEnvelope(envelope);
                }
            }
        },
        Qt::SingleShotConnection);

    connect(
        m_api,
        &ApiClient::fetchConversationMessagesFailed,
        this,
        [this](const QString& reason) {
            Q_UNUSED(reason)
            emit messageReceiveFailed(QStringLiteral("Failed to fetch conversation history."));
        },
        Qt::SingleShotConnection);

    m_api->fetchConversationMessages(conversationId);
}
