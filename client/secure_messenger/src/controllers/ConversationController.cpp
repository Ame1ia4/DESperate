#include "ConversationController.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
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

            QVector<ConversationItem> items;
            items.reserve(data.size());

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
                        m_deviceIds.insert(
                            item.conversationId,
                            item.deviceId);
                    }
                    if (!item.participant.isEmpty()) {
                        m_participants.insert(
                            item.conversationId,
                            item.participant);
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

    QSet<QString> cachedIds;

    const auto cachedMessages =
        m_messagesByConversation.value(
            conversationId);

    for (const auto& message : cachedMessages) {

        if (!message.isDeleted) {
            m_messageModel->addMessage(message);
            cachedIds.insert(message.id);
        }
    }

    const auto storedMessages =
        m_store->messagesForConversation(
            conversationId);

    for (const auto& message : storedMessages) {

        if (message.isDeleted ||
            cachedIds.contains(message.id)) {
            continue;
        }

        m_messageModel->addMessage(message);

        m_messagesByConversation
            [conversationId]
                .push_back(message);
    }

    // Kick off PQXDH session setup only if no session exists yet.
    const QString participant =
        m_participants.value(conversationId);

    if (!participant.isEmpty() &&
        !m_sessionFetchInFlight.contains(conversationId)) {

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
    // Only pullMessages from /messages/pending have the full envelope.
    // Once conversation is opened, MessageController will pullMessages on a timer.
    // For now, just emit to signal that local messages are ready.
    emit conversationOpened(conversationId);
}

void ConversationController::setupSessionAsync(
    const QString& conversationId,
    const QString& participant)
{
    m_sessionFetchInFlight.insert(conversationId);

    auto successConn = std::make_shared<QMetaObject::Connection>();
    auto failConn    = std::make_shared<QMetaObject::Connection>();

    *successConn = connect(
        m_apiClient,
        &ApiClient::fetchKeyBundleSucceeded,
        this,
        [this, conversationId, participant, failConn](const QJsonObject& bundle) {

            QObject::disconnect(*failConn);
            m_sessionFetchInFlight.remove(conversationId);

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
                // Session is only ready if crypto init succeeded AND the identity
                // is trusted. A fingerprint mismatch leaves sessionReady=false,
                // keeping the send/receive path blocked until the user resolves
                // the mismatch in VerifyDialog.
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
            m_sessionFetchInFlight.remove(conversationId);

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
    return m_deviceIds.value(
        conversationId, QString());
}

QString ConversationController::participantForConversation(
    const QString& conversationId) const
{
    return m_participants.value(
        conversationId, QString());
}

void ConversationController::reinitiateSession(const QString& conversationId)
{
    if (conversationId.isEmpty())
        return;
    m_cryptoClient->resetSession(conversationId);
    const QString participant = m_participants.value(conversationId);
    if (!participant.isEmpty())
        setupSessionAsync(conversationId, participant);
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
    const QString participant =
        m_participants.value(conversationId);
    if (participant.isEmpty())
        return;

    connect(
        m_apiClient,
        &ApiClient::fetchUserDevicesSucceeded,
        this,
        [this, conversationId](const QJsonArray& devices) {

            QStringList fingerprints;
            for (const auto& v : devices) {
                const QString fp =
                    v.toObject()
                     .value(QStringLiteral("fingerprint"))
                     .toString();
                if (!fp.isEmpty())
                    fingerprints.append(fp);
            }

            m_peerDeviceFingerprints[conversationId] = fingerprints;

            const int count = fingerprints.size();
            if (count != m_peerDeviceCount) {
                m_peerDeviceCount = count;
                emit peerDeviceCountChanged();
            }

            // Warn if the server is reporting more than one active device.
            // A legitimately multi-device user would have one pinned device
            // per conversation; >1 here means either the peer registered a
            // new device or a ghost device was injected.
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
