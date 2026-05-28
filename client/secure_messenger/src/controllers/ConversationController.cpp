#include "ConversationController.h"

#include <QDateTime>
#include <QUuid>

#include "src/models/ConversationModel.h"
#include "src/models/MessageModel.h"

#include "src/storage/TrustStore.h"

#include "src/services/ApiClient.h"
#include "src/services/CryptoServiceClient.h"

#include "src/storage/LocalMessageStore.h"

namespace {
constexpr int MAX_MESSAGE_LENGTH = 4096;
}

ConversationController::ConversationController(
    ApiClient* api,
    CryptoServiceClient* crypto,
    LocalMessageStore* store,
    TrustStore* trust,
    QObject* parent)
    : QObject(parent)
    , m_apiClient(api)
    , m_cryptoClient(crypto)
    , m_store(store)
    , m_trust(trust)
{
    m_conversationModel =
        new ConversationModel(this);

    m_messageModel =
        new MessageModel(this);
}

ConversationModel*
ConversationController::conversations() noexcept
{
    return m_conversationModel;
}

MessageModel*
ConversationController::messages() noexcept
{
    return m_messageModel;
}

QString
ConversationController::currentConversationId()
    const noexcept
{
    return m_currentConversationId;
}

void ConversationController::loadConversations()
{
    QVector<ConversationItem> items;

    ConversationItem alice;

    alice.conversationId = "conv-alice";
    alice.participant = "alice";
    alice.lastMessage =
        "Secure session established";
    alice.fingerprint =
        "7A:22:91:BC:11:90:EF";
    alice.updatedAt =
        QDateTime::currentDateTimeUtc();
    alice.unreadCount = 0;
    alice.verified = true;

    items.push_back(alice);

    ConversationItem bob;

    bob.conversationId = "conv-bob";
    bob.participant = "bob";
    bob.lastMessage =
        "Verify my fingerprint";
    bob.fingerprint =
        "90:11:0A:BC:2F:45:A1";
    bob.updatedAt =
        QDateTime::currentDateTimeUtc()
            .addSecs(-120);
    bob.unreadCount = 1;
    bob.verified = false;

    items.push_back(bob);

    m_conversationModel
        ->setConversations(items);

    // Seed local cache once.
    if (!m_messagesByConversation.isEmpty()) {
        return;
    }

    DecryptedMessage message;

    message.id =
        QUuid::createUuid().toString();

    message.conversationId =
        "conv-alice";

    message.senderDeviceId =
        "alice-phone";

    message.plaintext =
        "PQXDH secure session ready";

    message.timestamp =
        QDateTime::currentDateTimeUtc()
            .addSecs(-300);

    message.verificationState =
        VerificationState::Verified;

    m_messagesByConversation["conv-alice"]
        .push_back(message);
}

void ConversationController::openConversation(
    const QString& conversationId)
{
    if (conversationId.isEmpty()) {

        emit errorOccurred(
            "Conversation ID is required.");

        return;
    }

    if (m_currentConversationId !=
        conversationId) {

        m_currentConversationId =
            conversationId;

        emit currentConversationIdChanged();
    }

    m_messageModel->clear();

    // Cached messages first.
    const auto cachedMessages =
        m_messagesByConversation.value(
            conversationId);

    for (const auto& message :
         cachedMessages) {

        if (!message.isDeleted) {

            m_messageModel
                ->addMessage(message);
        }
    }

    // Persistent store replay.
    const auto storedMessages =
        m_store->messagesForConversation(
            conversationId);

    for (const auto& message :
         storedMessages) {

        if (message.isDeleted) {
            continue;
        }

        m_messageModel
            ->addMessage(message);

        m_messagesByConversation
            [conversationId]
                .push_back(message);
    }
}

void ConversationController::appendLocalMessage(
    const DecryptedMessage& message)
{
    if (!validateMessage(
            message.plaintext)) {

        emit errorOccurred(
            "Invalid message.");

        return;
    }

    m_messagesByConversation
        [message.conversationId]
            .push_back(message);

    if (message.conversationId ==
        m_currentConversationId) {

        m_messageModel
            ->addMessage(message);
    }
}

bool ConversationController::verifyFingerprint(
    const QString& conversationId,
    const QString& fingerprint)
{
    const QString pinned =
        m_conversationModel
            ->fingerprintForConversation(
                conversationId);

    // TOFU:
    // First seen fingerprint becomes trusted.
    if (pinned.isEmpty()) {

        return m_conversationModel
            ->setFingerprintForConversation(
                conversationId,
                fingerprint,
                true);
    }

    if (QString::compare(
            pinned,
            fingerprint,
            Qt::CaseSensitive) != 0) {

        m_conversationModel
            ->setFingerprintForConversation(
                conversationId,
                pinned,
                false);

        emit fingerprintMismatch(
            pinned,
            fingerprint);

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

    return plaintext.size() <=
           MAX_MESSAGE_LENGTH;
}