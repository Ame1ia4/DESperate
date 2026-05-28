#include "ConversationController.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QUuid>
#include <QDateTime>

#include "src/services/ApiClient.h"
#include "src/services/CryptoServiceClient.h"

namespace {
constexpr int MAX_MESSAGE_LENGTH = 4096;
}

ConversationController::ConversationController(
    ApiClient* api,
    CryptoServiceClient* crypto,
    QObject* parent)
    : QObject(parent)
    , m_apiClient(api)
    , m_cryptoClient(crypto)
{
}

ConversationModel* ConversationController::conversations() noexcept
{
    return &m_conversationModel;
}

MessageModel* ConversationController::messages() noexcept
{
    return &m_messageModel;
}

QString ConversationController::currentConversationId() const noexcept
{
    return m_currentConversationId;
}

void ConversationController::loadConversations()
{
    // Seed conversations are demo placeholders until backend fetch is wired.
    QVector<ConversationItem> items;

    ConversationItem alice;
    alice.conversationId = "conv-alice";
    alice.participant = "alice";
    alice.lastMessage = "Ready when you are.";
    alice.fingerprint = "7A:22:91:BC:11:90:EF";
    alice.updatedAt = QDateTime::currentDateTimeUtc();
    alice.unreadCount = 0;
    alice.verified = true;
    items.push_back(alice);

    ConversationItem bob;
    bob.conversationId = "conv-bob";
    bob.participant = "bob";
    bob.lastMessage = "Let us verify fingerprints.";
    bob.fingerprint = "90:11:0A:BC:2F:45:A1";
    bob.updatedAt = QDateTime::currentDateTimeUtc().addSecs(-120);
    bob.unreadCount = 1;
    bob.verified = false;
    items.push_back(bob);

    if (m_messagesByConversation.isEmpty()) {
        DecryptedMessage incomingAlice;
        incomingAlice.id = QUuid::createUuid().toString();
        incomingAlice.conversationId = "conv-alice";
        incomingAlice.senderDeviceId = "alice-phone";
        incomingAlice.plaintext = "PQXDH secure session ready";
        incomingAlice.timestamp = QDateTime::currentDateTimeUtc().addSecs(-300);
        incomingAlice.verificationState = VerificationState::Verified;
        m_messagesByConversation["conv-alice"].push_back(incomingAlice);

        DecryptedMessage outgoingAlice;
        outgoingAlice.id = QUuid::createUuid().toString();
        outgoingAlice.conversationId = "conv-alice";
        outgoingAlice.senderDeviceId = "self";
        outgoingAlice.plaintext = "Great, sending encrypted messages now.";
        outgoingAlice.timestamp = QDateTime::currentDateTimeUtc().addSecs(-240);
        outgoingAlice.verificationState = VerificationState::Verified;
        m_messagesByConversation["conv-alice"].push_back(outgoingAlice);
    }

    m_conversationModel.setConversations(items);
}

void ConversationController::openConversation(
    const QString& conversationId)
{
    if (m_currentConversationId != conversationId) {
        m_currentConversationId = conversationId;
        emit currentConversationIdChanged();
    }

    m_messageModel.clear();

    const auto conversationMessages = m_messagesByConversation.value(conversationId);
    for (const auto& msg : conversationMessages) {
        if (!msg.isDeleted) {
            m_messageModel.addMessage(msg);
        }
    }
}

void ConversationController::sendMessage(
    const QString& conversationId,
    const QString& plaintext)
{
    if (conversationId.isEmpty()) {
        emit errorOccurred("Select a conversation first.");
        return;
    }

    if (!validateMessage(plaintext)) {
        emit errorOccurred("Invalid message payload");
        return;
    }

    const QByteArray associatedData =
        buildAssociatedData(conversationId);
    Q_UNUSED(associatedData)
    // Recipient routing must come from conversation/device membership.
    // Placeholder while endpoint discovery is wired.
    const QString recipientDeviceId = "recipient-device-id";
    const QJsonObject envelope =
        m_cryptoClient->encryptMessage(
            plaintext,
            recipientDeviceId,
            conversationId);

    if (envelope.isEmpty()) {
        emit errorOccurred("Encryption failed");
        return;
    }

    m_apiClient->sendMessage(envelope); // ciphertext + metadata only

    DecryptedMessage item;
    item.id = QUuid::createUuid().toString();
    item.senderDeviceId = "self";
    item.conversationId = conversationId;
    item.plaintext = plaintext;
    item.timestamp = QDateTime::currentDateTimeUtc();
    item.verificationState = VerificationState::Verified;

    m_messagesByConversation[conversationId].push_back(item);
    m_messageModel.addMessage(item);
}

bool ConversationController::verifyFingerprint(
    const QString& conversationId,
    const QString& fingerprint)
{
    const QString pinned =
        m_conversationModel
            .fingerprintForConversation(conversationId);

    // TOFU: first seen identity is pinned locally on the client.
    if (pinned.isEmpty()) {
        return m_conversationModel
            .setFingerprintForConversation(conversationId,
                                           fingerprint,
                                           true);
    }

    if (QString::compare(pinned, fingerprint, Qt::CaseSensitive) != 0) {
        m_conversationModel
            .setFingerprintForConversation(conversationId,
                                           pinned,
                                           false);
        emit fingerprintMismatch(pinned, fingerprint);
        return false;
    }

    return true;
}

bool ConversationController::validateMessage(
    const QString& plaintext) const
{
    if (plaintext.isEmpty()) {
        return false;
    }

    if (plaintext.size() > MAX_MESSAGE_LENGTH) {
        return false;
    }

    return true;
}

QByteArray ConversationController::buildAssociatedData(
    const QString& conversationId) const
{
    QJsonObject ad {
        {"conversation_id", conversationId},
        {"timestamp",
         QDateTime::currentDateTimeUtc().toString(Qt::ISODate)}
    };

    return QJsonDocument(ad).toJson(QJsonDocument::Compact);
}