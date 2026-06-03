#pragma once

#include <QObject>
#include <QString>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "src/models/ConversationModel.h"
#include "src/models/MessageModel.h"
#include "src/types/Types.h"

class ApiClient;
class CryptoServiceClient;
class LocalMessageStore;
class TrustStore;

class ConversationController : public QObject
{
    Q_OBJECT

    Q_PROPERTY(
        ConversationModel* conversations
            READ conversations
                CONSTANT)

    Q_PROPERTY(
        MessageModel* messages
            READ messages
                CONSTANT)

    Q_PROPERTY(
        QString currentConversationId
            READ currentConversationId
                NOTIFY currentConversationIdChanged)

    Q_PROPERTY(
        bool sessionReady
            READ sessionReady
                NOTIFY sessionReadyChanged)

    // C1 fix: true while a fingerprint mismatch is unresolved for the
    // current conversation. Drives the blocked banner in MessageView.qml.
    Q_PROPERTY(
        bool identityMismatch
            READ identityMismatch
                NOTIFY identityMismatchChanged)

    // H4 fix: number of active devices the server reports for the peer
    // in the current conversation. A value >1 is shown as a warning in
    // ConversationList so the user can detect ghost devices.
    Q_PROPERTY(
        int peerDeviceCount
            READ peerDeviceCount
                NOTIFY peerDeviceCountChanged)

public:
    explicit ConversationController(
        ApiClient* api,
        CryptoServiceClient* crypto,
        LocalMessageStore* store,
        TrustStore* trust,
        QObject* parent = nullptr);

    ConversationModel* conversations() noexcept;

    MessageModel* messages() noexcept;

    QString currentConversationId() const noexcept;

    bool sessionReady() const noexcept;

    bool identityMismatch() const noexcept;

    int peerDeviceCount() const noexcept;

public slots:
    void loadConversations();

    void openConversation(
        const QString& conversationId);

    void appendLocalMessage(
        const DecryptedMessage& message);

    bool verifyFingerprint(
        const QString& conversationId,
        const QString& fingerprint);

    Q_INVOKABLE QString deviceIdForConversation(
        const QString& conversationId) const;

    Q_INVOKABLE QString participantForConversation(
        const QString& conversationId) const;

    Q_INVOKABLE void createChat(const QString& username);

    void reinitiateSession(const QString& conversationId);

    // H4 fix: fetch all active devices for the peer and compare against
    // the single device_id the server returned in the conversation list.
    // Emits ghostDeviceDetected if the server reports additional devices.
    Q_INVOKABLE void fetchPeerDevices(const QString& conversationId);
    void updateMessageId(const QString& oldId, const QString& newId);
    void removeLocalMessage(const QString& messageId);
    void markLocalRevoked(const QString& messageId);
    void markLocalDeleted(const QString& messageId);

signals:
    void currentConversationIdChanged();

    void sessionReadyChanged();

    // Emitted after a conversation is opened (id set and messages cleared/loaded)
    void conversationOpened(QString conversationId);

    void errorOccurred(
        QString reason);

    void createChatFailed(QString reason);

    void fingerprintMismatch(
        QString expectedFingerprint,
        QString receivedFingerprint);

    // C1 fix
    void identityMismatchChanged();

    // H4 fix: emitted when the server reports more active devices for the
    // peer than expected. deviceCount is the total the server returned.
    void ghostDeviceDetected(QString conversationId, int deviceCount);

    void peerDeviceCountChanged();

private:
    // Fetch the participant's public key bundle and establish the PQXDH session.
    void setupSessionAsync(
        const QString& conversationId,
        const QString& participant);

    bool validateMessage(
        const QString& plaintext) const;

private:
    ApiClient* m_apiClient = nullptr;
    CryptoServiceClient* m_cryptoClient = nullptr;
    LocalMessageStore* m_store = nullptr;
    TrustStore* m_trust = nullptr;

    ConversationModel* m_conversationModel = nullptr;
    MessageModel* m_messageModel = nullptr;

    QString m_currentConversationId;

    bool m_sessionReady = true;

    // conversationId → cached decrypted messages for that conversation
    std::unordered_map<std::string, std::vector<DecryptedMessage>>
        m_messagesByConversation;

    // conversationId → other participant's username
    std::unordered_map<std::string, std::string> m_participants;

    // conversationId → other participant's device ID
    std::unordered_map<std::string, std::string> m_deviceIds;

    // conversationIds for which a session fetch is already in-flight
    std::set<std::string> m_sessionFetchInFlight;

    // C1 fix: true when a fingerprint mismatch is unresolved
    bool m_identityMismatch = false;

    // H4 fix: number of active devices the server last reported for the
    // peer in the current conversation (0 = not yet fetched)
    int m_peerDeviceCount = 0;

    // conversationId → list of device fingerprints reported by the server
    std::unordered_map<std::string, std::vector<std::string>> m_peerDeviceFingerprints;
};
