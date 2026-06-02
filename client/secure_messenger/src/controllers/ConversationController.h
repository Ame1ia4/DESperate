#pragma once

#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>
#include <QVector>

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

    QHash<
        QString,
        QVector<DecryptedMessage>>
        m_messagesByConversation;

    // conversationId → other participant's username
    QHash<QString, QString> m_participants;

    // conversationId → other participant's device ID
    QHash<QString, QString> m_deviceIds;

    // conversationIds for which a session fetch is already in-flight
    QSet<QString> m_sessionFetchInFlight;
};
