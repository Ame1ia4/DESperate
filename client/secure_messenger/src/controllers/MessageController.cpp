#include "MessageController.h"

#include <QClipboard>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QGuiApplication>
#include <QJsonArray>
#include <QStandardPaths>
#include <QTextStream>
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

    // When the server responds to POST /messages, swap the client temp ID for the server DB UUID
    // in the model, the local store, AND the ConversationController's in-memory cache.
    // All three must be in sync so that delete/revoke still use the correct ID after navigation.
    connect(m_api, &ApiClient::messageSentToServer, this,
        [this](const QString& localId, const QString& serverId) {
            m_model->updateMessageId(localId, serverId);
            m_store->updateMessageId(localId, serverId);
            m_conversations->updateMessageId(localId, serverId);
        });

    connect(m_api, &ApiClient::deleteMessageSucceeded, this, [this](const QString& messageId) {
        m_model->removeMessage(messageId);
    });

    // Revoke: mark the sender's own bubble with a small indicator, persist the state,
    // but keep the original message text visible (only the recipient lost access).
    connect(m_api, &ApiClient::revokeMessageSucceeded, this, [this](const QString& messageId) {
        m_model->markRevoked(messageId);
        m_store->markMessageRevoked(messageId);
        m_conversations->markLocalRevoked(messageId);
        emit messageRevokeSucceeded();
    });

    connect(m_api, &ApiClient::revokeMessageFailed, this, [this](const QString&) {
        emit messageRevokeFailed();
    });

    connect(m_conversations, &ConversationController::sessionReadyChanged, this, [this]() {
        if (!m_conversations->sessionReady()) return;
        const QString convId = m_conversations->currentConversationId();
        if (!m_pendingForwards.contains(convId)) return;
        const QString text = m_pendingForwards.take(convId);
        sendText(convId, text);
    });
}

void MessageController::deleteMessage(const QString& messageId)
{
    if (messageId.isEmpty()) return;
    // Mark deleted in all three layers so the bubble stays but shows "Message deleted".
    m_model->markDeleted(messageId);
    m_store->markMessageDeleted(messageId);
    m_conversations->markLocalDeleted(messageId);
    m_api->deleteMessage(messageId);
}

void MessageController::revokeMessage(const QString& messageId, const QString& recipientDeviceId)
{
    m_api->revokeMessage(messageId, recipientDeviceId);
}

void MessageController::forwardMessage(const QString& toUsername, const QString& plaintext)
{
    const QString trimmed = toUsername.trimmed();
    if (trimmed.isEmpty() || plaintext.isEmpty()) return;

    // Store plaintext keyed by the conversation ID we're about to create/open.
    // The ID is captured from createConversationSucceeded before createChat fires it.
    connect(
        m_api,
        &ApiClient::createConversationSucceeded,
        this,
        [this, plaintext](const QString& conversationId) {
            m_pendingForwards.insert(conversationId, plaintext);
        },
        Qt::SingleShotConnection);

    // createChat handles conversation creation, loadConversations (for device IDs),
    // openConversation, and PQXDH session setup. sessionReadyChanged fires when ready.
    m_conversations->createChat(trimmed);
}

void MessageController::downloadMessage(const QString& messageId, const QString& plaintext)
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    if (dir.isEmpty()) {
        emit messageDownloadFailed(QStringLiteral("Cannot locate Downloads folder."));
        return;
    }

    const QString timestamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"));
    const QString path      = QDir(dir).filePath(QStringLiteral("message_%1.txt").arg(timestamp));

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        emit messageDownloadFailed(QStringLiteral("Failed to save: ") + file.errorString());
        return;
    }

    QTextStream out(&file);
    out << "Message ID: " << messageId << "\n";
    out << "Downloaded: " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n\n";
    out << plaintext << "\n";
    file.close();

    emit messageDownloaded(path);
}

QString MessageController::ciphertextForMessage(const QString& messageId) const
{
    const QByteArray ct = m_store->ciphertextForMessage(messageId);
    return ct.isEmpty() ? QString{} : QString::fromLatin1(ct.toHex());
}

void MessageController::copyCiphertext(const QString& messageId)
{
    const QByteArray ct = m_store->ciphertextForMessage(messageId);
    if (ct.isEmpty()) {
        emit ciphertextCopyFailed();
        return;
    }
    QGuiApplication::clipboard()->setText(QString::fromLatin1(ct.toHex()));
    emit ciphertextCopied();
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

    qDebug() << "[SEND] encrypted OK, posting to server | conv:" << pending.conversationId
             << "| ciphertext len:" << envelope["ciphertext"].toString().length();

    // Use a brace-free UUID as the local temp ID.
    // The server will assign its own DB UUID; messageSentToServer swaps it in once the
    // POST /messages response arrives so delete/revoke can reference the correct ID.
    const QString localId = QUuid::createUuid().toString(QUuid::WithoutBraces);

    fullEnvelope["id"] = localId;
    m_store->storeOutgoingMessage(fullEnvelope);
    m_api->sendMessage(fullEnvelope, localId);

    // Optimistic UI update.
    DecryptedMessage message;

    message.id = localId;

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

    m_store->storeOutgoingMessage(envelope);
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
        // Persist the envelope so "Copy ciphertext" works even for messages
        // we cannot decrypt (e.g. our own outgoing messages in history).
        m_store->storeOutgoingMessage(envelope);

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

    connect(
        m_api,
        &ApiClient::pullNoticesSucceeded,
        this,
        [this](const QJsonArray& notices) {
            for (const auto& v : notices) {
                const auto notice    = v.toObject();
                const QString msgId  = notice.value("message_id").toString();
                const QString type   = notice.value("type").toString();
                if (msgId.isEmpty()) continue;

                if (type == QStringLiteral("deleted")) {
                    qDebug() << "[NOTICE] deletion:" << msgId;
                    m_model->markDeleted(msgId);
                    m_store->markMessageDeleted(msgId);
                    m_conversations->markLocalDeleted(msgId);
                } else if (type == QStringLiteral("revoked")) {
                    qDebug() << "[NOTICE] revoke:" << msgId;
                    m_model->markRevoked(msgId);
                    m_store->markMessageRevoked(msgId);
                    m_conversations->markLocalRevoked(msgId);
                }
            }
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
