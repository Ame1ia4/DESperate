#include "ConversationController.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonObject>
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
    connect(
        m_apiClient,
        &ApiClient::fetchConversationsSucceeded,
        this,
        [this](const QJsonArray& data) {

            QVector<ConversationItem> items;
            items.reserve(data.size());

            m_deviceIds.clear();

            for (const auto& value : data) {

                const QJsonObject obj =
                    value.toObject();

                ConversationItem item;

                item.conversationId =
                    obj.value("id").toString();

                item.participant =
                    obj.value("participant")
                        .toString();

                item.deviceId =
                    obj.value("device_id")
                        .toString();

                item.lastMessage =
                    obj.value("last_message")
                        .toString();

                item.fingerprint =
                    obj.value("fingerprint")
                        .toString();

                item.updatedAt =
                    QDateTime::fromString(
                        obj.value("updated_at")
                            .toString(),
                        Qt::ISODateWithMs);

                item.unreadCount =
                    obj.value("unread_count")
                        .toInt(0);

                item.verified =
                    m_trust->isVerified(
                        item.participant);

                if (!item.conversationId.isEmpty() &&
                    !item.deviceId.isEmpty()) {

                    m_deviceIds.insert(
                        item.conversationId,
                        item.deviceId);
                }

                items.push_back(item);
            }

            m_conversationModel
                ->setConversations(items);
        },
        Qt::SingleShotConnection);

    connect(
        m_apiClient,
        &ApiClient::fetchConversationsFailed,
        this,
        [this](const QString& reason) {

            emit errorOccurred(reason);
        },
        Qt::SingleShotConnection);

    m_apiClient->fetchConversations();
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

QString ConversationController::deviceIdForConversation(
    const QString& conversationId) const
{
    return m_deviceIds.value(
        conversationId, QString());
}