#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QHash>
#include <QVector>

#include "../models/ConversationModel.h"
#include "../models/MessageModel.h"
#include "../types/Types.h"

class ApiClient;
class CryptoServiceClient;

class ConversationController final : public QObject
{
    Q_OBJECT

    Q_PROPERTY(ConversationModel* conversations
                   READ conversations
                       CONSTANT)

    Q_PROPERTY(MessageModel* messages
                   READ messages
                       CONSTANT)

    Q_PROPERTY(QString currentConversationId
                   READ currentConversationId
                       NOTIFY currentConversationIdChanged)

public:
    explicit ConversationController(ApiClient* api,
                                    CryptoServiceClient* crypto,
                                    QObject* parent = nullptr);

    ConversationModel* conversations() noexcept;
    MessageModel* messages() noexcept;
    QString currentConversationId() const noexcept;

    Q_INVOKABLE void loadConversations();

    Q_INVOKABLE void openConversation(const QString& conversationId);

    Q_INVOKABLE void sendMessage(const QString& conversationId,
                                 const QString& plaintext);

    Q_INVOKABLE bool verifyFingerprint(const QString& conversationId,
                                       const QString& fingerprint);

signals:
    void errorOccurred(const QString& message);
    void fingerprintMismatch(const QString& expected,
                             const QString& received);
    void currentConversationIdChanged();

private:
    bool validateMessage(const QString& plaintext) const;

    QByteArray buildAssociatedData(const QString& conversationId) const;

private:
    ConversationModel m_conversationModel;
    MessageModel m_messageModel;
    QHash<QString, QVector<DecryptedMessage>> m_messagesByConversation;

    ApiClient* m_apiClient;
    CryptoServiceClient* m_cryptoClient;
    QString m_currentConversationId;
};