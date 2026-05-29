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

signals:
    void currentConversationIdChanged();

    void errorOccurred(
        QString reason);

    void fingerprintMismatch(
        QString expectedFingerprint,
        QString receivedFingerprint);

private:
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

    QHash<
        QString,
        QVector<DecryptedMessage>>
        m_messagesByConversation;

    QHash<QString, QString>
        m_deviceIds;
};