
#pragma once

#include <QObject>
#include <QHash>
#include <QJsonObject>
#include <QString>
#include <QVector>

#include "src/types/Types.h"

    class LocalMessageStore : public QObject
{
    Q_OBJECT

public:
    explicit LocalMessageStore(
        QObject* parent = nullptr);

    // Encrypted envelope persistence
    void storeOutgoingMessage(
        const QJsonObject& envelope);

    void storeOutgoingEnvelope(
        const MessageEnvelope& envelope);

    QVector<MessageEnvelope> envelopes()
        const;

    QVector<MessageEnvelope>
    envelopesForConversation(
        const QString& conversationId)
        const;

    // Local decrypted cache
    void storeDecryptedMessage(
        const DecryptedMessage& message);

    QVector<DecryptedMessage>
    decryptedMessages() const;

    QVector<DecryptedMessage>
    messagesForConversation(
        const QString& conversationId)
        const;

    bool containsMessage(
        const QString& messageId)
        const;

    void updateMessageId(
        const QString& oldId,
        const QString& newId);

    void removeDecryptedMessage(const QString& messageId);
    void markMessageRevoked(const QString& messageId);
    void markMessageDeleted(const QString& messageId);

    void clearConversation(
        const QString& conversationId);

    void clearAll();

private:
    QVector<MessageEnvelope>
        m_envelopes;

    QVector<DecryptedMessage>
        m_decryptedMessages;

    QHash<QString, int>
        m_messageIndex;

    void saveState() const;
};
