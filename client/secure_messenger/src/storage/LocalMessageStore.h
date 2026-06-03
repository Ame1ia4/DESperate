
#pragma once

#include <QObject>
#include <QJsonObject>
#include <QString>
#include <string>
#include <unordered_map>
#include <vector>

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

    std::vector<MessageEnvelope> envelopes()
        const;

    std::vector<MessageEnvelope>
    envelopesForConversation(
        const QString& conversationId)
        const;

    // Local decrypted cache
    void storeDecryptedMessage(
        const DecryptedMessage& message);

    std::vector<DecryptedMessage>
    decryptedMessages() const;

    std::vector<DecryptedMessage>
    messagesForConversation(
        const QString& conversationId)
        const;

    bool containsMessage(
        const QString& messageId)
        const;

    QByteArray ciphertextForMessage(
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
    std::vector<MessageEnvelope>
        m_envelopes;

    std::vector<DecryptedMessage>
        m_decryptedMessages;

    // O(1) message ID lookup: maps message ID (std::string) to index in m_decryptedMessages
    std::unordered_map<std::string, int>
        m_messageIndex;

    void saveState() const;
};
