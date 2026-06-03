#include "ConversationController.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUuid>
#include <algorithm>
#include <unordered_set>

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

bool ConversationController::sessionReady() const noexcept
{
    return m_sessionReady;
}

bool ConversationController::identityMismatch() const noexcept
{
    return m_identityMismatch;
}

int ConversationController::peerDeviceCount() const noexcept
{
    return m_peerDeviceCount;
}

void ConversationController::loadConversations()
{
    connect(
        m_apiClient,
        &ApiClient::fetchConversationsSucceeded,
        this,
        [this](const QJsonArray& data) {

            std::vector<ConversationItem> items;
            items.reserve(static_cast<size_t>(data.size()));

            m_deviceIds.clear();
            m_participants.clear();

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

                if (!item.conversationId.isEmpty()) {
                    if (!item.deviceId.isEmpty()) {
                        m_deviceIds[item.conversationId.toStdString()] =
                            item.deviceId.toStdString();
                    }
                    if (!item.participant.isEmpty()) {
                        m_participants[item.conversationId.toStdString()] =
                            item.participant.toStdString();
                    }
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

    const std::string convIdStr = conversationId.toStdString();

    // Merge cache and store (store may have messages from a previous session).
    std::unordered_set<std::string> seenIds;
    auto cacheIt = m_messagesByConversation.find(convIdStr);
    if (cacheIt != m_messagesByConversation.end()) {
        for (const auto& message : cacheIt->second)
            seenIds.insert(message.id.toStdString());
    }

    for (const auto& message : m_store->messagesForConversation(conversationId)) {
        if (!seenIds.count(message.id.toStdString())) {
            seenIds.insert(message.id.toStdString());
            m_messagesByConversation[convIdStr].push_back(message);
        }
    }

    // Sort the merged list chronologically so the view always shows oldest→newest.
    auto& convMessages = m_messagesByConversation[convIdStr];
    std::sort(convMessages.begin(), convMessages.end(),
        [](const DecryptedMessage& a, const DecryptedMessage& b) {
            return a.timestamp < b.timestamp;
        });

    for (const auto& message : convMessages)
        m_messageModel->addMessage(message);

    // Kick off PQXDH session setup only if no session exists yet.
    auto partIt = m_participants.find(convIdStr);
    const QString participant = (partIt != m_participants.end())
        ? QString::fromStdString(partIt->second)
        : QString{};

    if (!participant.isEmpty() &&
        !m_sessionFetchInFlight.count(convIdStr)) {

        if (m_cryptoClient->hasSession(conversationId)) {
            // Session already on disk — no need to do PQXDH again.
            m_sessionReady = true;
            emit sessionReadyChanged();
        } else {
            m_sessionReady = false;
            emit sessionReadyChanged();
            setupSessionAsync(conversationId, participant);
        }
    }
    // NOTE: Not fetching history from /conversations/:id/messages because those messages
    // lack the initiation_bundle (PQXDH key material) needed for decryption.
    emit conversationOpened(conversationId);
}

void ConversationController::setupSessionAsync(
    const QString& conversationId,
    const QString& participant)
{
    m_sessionFetchInFlight.insert(conversationId.toStdString());

    auto successConn = std::make_shared<QMetaObject::Connection>();
    auto failConn    = std::make_shared<QMetaObject::Connection>();

    *successConn = connect(
        m_apiClient,
        &ApiClient::fetchKeyBundleSucceeded,
        this,
        [this, conversationId, participant, failConn](const QJsonObject& bundle) {

            QObject::disconnect(*failConn);
            m_sessionFetchInFlight.erase(conversationId.toStdString());

            const QByteArray bundleJson =
                QJsonDocument(bundle).toJson(QJsonDocument::Compact);

            const bool ok = m_cryptoClient->initiateSession(conversationId, bundleJson);

            // C1 fix: verify the peer's identity fingerprint via TrustStore
            // immediately after session setup, before allowing any messages.
            //
            // TOFU semantics (TrustStore::verifyIdentity):
            //   - First contact: the fingerprint is pinned locally and trusted.
            //   - Subsequent contacts: the received fingerprint is compared against
            //     the locally pinned one. A mismatch fires fingerprintMismatch and
            //     blocks the session until the user confirms out-of-band.
            //
            // ik_sig_pub is the 2624-byte hybrid Ed25519+ML-DSA-87 identity key
            // from GET /keys/:username — the same key the crypto service verifies
            // every message signature against, so it is the correct fingerprint.
            const QString receivedFingerprint =
                bundle.value("ik_sig_pub").toString();

            const bool trusted =
                (!participant.isEmpty() && !receivedFingerprint.isEmpty())
                    ? m_trust->verifyIdentity(participant, receivedFingerprint)
                    : false;

            if (conversationId == m_currentConversationId) {
                m_sessionReady = ok && trusted;
                emit sessionReadyChanged();

                // C1 fix: drive identityMismatch so the QML banner can bind to it.
                if (m_identityMismatch != !trusted) {
                    m_identityMismatch = !trusted;
                    emit identityMismatchChanged();
                }

                if (!ok)
                    qWarning() << "initiateSession failed for conversation" << conversationId
                               << ":" << m_cryptoClient->lastError();
                if (!trusted)
                    qWarning() << "Identity verification failed for" << participant
                               << "— fingerprint mismatch or empty bundle field.";
            }
        },
        Qt::SingleShotConnection);

    *failConn = connect(
        m_apiClient,
        &ApiClient::fetchKeyBundleFailed,
        this,
        [this, conversationId, successConn](const QString& reason) {

            QObject::disconnect(*successConn);
            m_sessionFetchInFlight.erase(conversationId.toStdString());

            qWarning() << "fetchKeyBundle failed for conversation"
                       << conversationId << ":" << reason;

            if (conversationId == m_currentConversationId) {
                m_sessionReady = false;
                emit sessionReadyChanged();
            }
        },
        Qt::SingleShotConnection);

    m_apiClient->fetchKeyBundle(participant);
}

void ConversationController::appendLocalMessage(
    const DecryptedMessage& message)
{
    // Placeholders for deleted/revoked messages have empty plaintext — allow them through.
    if (!message.isDeleted && !message.revoked && !validateMessage(message.plaintext)) {
        emit errorOccurred("Invalid message.");
        return;
    }

    m_messagesByConversation[message.conversationId.toStdString()]
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

    if (pinned.isEmpty()) {

        const bool ok = m_conversationModel
            ->setFingerprintForConversation(
                conversationId,
                fingerprint,
                true);

        // First contact — pin accepted, clear any stale mismatch state.
        if (ok && m_identityMismatch) {
            m_identityMismatch = false;
            emit identityMismatchChanged();
        }
        return ok;
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

    // Fingerprints match — ensure mismatch flag is cleared.
    if (m_identityMismatch) {
        m_identityMismatch = false;
        emit identityMismatchChanged();
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
    auto it = m_deviceIds.find(conversationId.toStdString());
    if (it == m_deviceIds.end()) return {};
    return QString::fromStdString(it->second);
}

QString ConversationController::participantForConversation(
    const QString& conversationId) const
{
    auto it = m_participants.find(conversationId.toStdString());
    if (it == m_participants.end()) return {};
    return QString::fromStdString(it->second);
}

void ConversationController::reinitiateSession(const QString& conversationId)
{
    if (conversationId.isEmpty())
        return;
    m_cryptoClient->resetSession(conversationId);
    auto it = m_participants.find(conversationId.toStdString());
    if (it != m_participants.end())
        setupSessionAsync(conversationId, QString::fromStdString(it->second));
}

void ConversationController::fetchPeerDevices(
    const QString& conversationId)
{
    // H4 fix: fetch all active devices for the peer and compare the count
    // against the single device_id the conversation list returned.
    //
    // A server that has inserted a ghost device row will return >1 device
    // here. We surface the count to the user via peerDeviceCount so they
    // can notice and investigate out-of-band.
    //
    // Note: a fully compromised server can suppress ghost devices from this
    // response too. This is a best-effort detection mechanism, not a
    // cryptographic guarantee — it is documented as a known limitation.
    auto partIt = m_participants.find(conversationId.toStdString());
    if (partIt == m_participants.end()) return;
    const QString participant = QString::fromStdString(partIt->second);

    connect(
        m_apiClient,
        &ApiClient::fetchUserDevicesSucceeded,
        this,
        [this, conversationId](const QJsonArray& devices) {

            std::vector<std::string> fingerprints;
            fingerprints.reserve(static_cast<size_t>(devices.size()));

            for (const auto& v : devices) {
                const QString fp =
                    v.toObject()
                     .value(QStringLiteral("fingerprint"))
                     .toString();
                if (!fp.isEmpty())
                    fingerprints.push_back(fp.toStdString());
            }

            m_peerDeviceFingerprints[conversationId.toStdString()] = fingerprints;

            const int count = static_cast<int>(fingerprints.size());
            if (count != m_peerDeviceCount) {
                m_peerDeviceCount = count;
                emit peerDeviceCountChanged();
            }

            // Warn if the server is reporting more than one active device.
            if (count > 1) {
                qWarning() << "H4: peer for conversation" << conversationId
                           << "has" << count << "active devices — possible ghost device.";
                emit ghostDeviceDetected(conversationId, count);
            }
        },
        Qt::SingleShotConnection);

    connect(
        m_apiClient,
        &ApiClient::fetchUserDevicesFailed,
        this,
        [this](const QString& reason) {
            qWarning() << "fetchPeerDevices failed:" << reason;
        },
        Qt::SingleShotConnection);

    m_apiClient->fetchUserDevices(participant);
}

void ConversationController::updateMessageId(const QString& oldId, const QString& newId)
{
    if (oldId.isEmpty() || newId.isEmpty() || oldId == newId) return;
    for (auto& [key, msgList] : m_messagesByConversation) {
        for (auto& msg : msgList) {
            if (msg.id == oldId) {
                msg.id = newId;
                return;
            }
        }
    }
}

void ConversationController::removeLocalMessage(const QString& messageId)
{
    for (auto& [key, msgList] : m_messagesByConversation) {
        auto msgIt = std::find_if(msgList.begin(), msgList.end(),
            [&messageId](const DecryptedMessage& m) { return m.id == messageId; });
        if (msgIt != msgList.end()) {
            msgList.erase(msgIt);
            return;
        }
    }
}

void ConversationController::markLocalRevoked(const QString& messageId)
{
    for (auto& [key, msgList] : m_messagesByConversation) {
        for (auto& msg : msgList) {
            if (msg.id == messageId) {
                msg.revoked = true;
                return;
            }
        }
    }
}

void ConversationController::markLocalDeleted(const QString& messageId)
{
    for (auto& [key, msgList] : m_messagesByConversation) {
        for (auto& msg : msgList) {
            if (msg.id == messageId) {
                msg.isDeleted = true;
                return;
            }
        }
    }
}

void ConversationController::createChat(const QString& username)
{
    if (username.trimmed().isEmpty()) {
        emit createChatFailed(QStringLiteral("Username cannot be empty."));
        return;
    }

    connect(
        m_apiClient,
        &ApiClient::createConversationSucceeded,
        this,
        [this](const QString& conversationId) {
            // loadConversations registers its fetchConversationsSucceeded handler first.
            // Our handler connects after, so Qt fires them in order: m_participants is
            // populated before openConversation runs and setupSessionAsync is skipped.
            loadConversations();
            connect(
                m_apiClient,
                &ApiClient::fetchConversationsSucceeded,
                this,
                [this, conversationId](const QJsonArray&) {
                    openConversation(conversationId);
                },
                Qt::SingleShotConnection);
        },
        Qt::SingleShotConnection);

    connect(
        m_apiClient,
        &ApiClient::createConversationFailed,
        this,
        [this](const QString& reason) {
            emit createChatFailed(reason);
        },
        Qt::SingleShotConnection);

    m_apiClient->createConversation(username);
}
