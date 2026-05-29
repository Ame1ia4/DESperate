
#include "LocalMessageStore.h"

#include <QDateTime>

    LocalMessageStore::LocalMessageStore(
        QObject* parent)
    : QObject(parent)
{
}

void LocalMessageStore::storeOutgoingMessage(
    const QJsonObject& envelope)
{
    MessageEnvelope typedEnvelope;

    typedEnvelope.id =
        envelope.value("id")
            .toString();

    typedEnvelope.conversationId =
        envelope.value(
                    "conversation_id")
            .toString();

    typedEnvelope.senderDeviceId =
        envelope.value(
                    "sender_device_id")
            .toString();

    typedEnvelope.ciphertext =
        QByteArray::fromBase64(
            envelope.value(
                        "ciphertext")
                .toString()
                .toUtf8());

    typedEnvelope.nonce =
        QByteArray::fromBase64(
            envelope.value(
                        "nonce")
                .toString()
                .toUtf8());

    typedEnvelope.associatedData =
        QByteArray::fromBase64(
            envelope.value(
                        "associated_data")
                .toString()
                .toUtf8());

    typedEnvelope.txHash =
        envelope.value(
                    "tx_hash")
            .toString();

    typedEnvelope.merkleRoot =
        envelope.value(
                    "merkle_root")
            .toString();

    typedEnvelope.timestamp =
        QDateTime::currentDateTimeUtc();

    storeOutgoingEnvelope(
        typedEnvelope);
}

void LocalMessageStore::storeOutgoingEnvelope(
    const MessageEnvelope& envelope)
{
    if (envelope.id.isEmpty()) {
        return;
    }

    for (const auto& existing :
         m_envelopes) {

        if (existing.id ==
            envelope.id) {

            return;
        }
    }

    // Intentionally envelope-only.
    // Plaintext is never persisted here.
    m_envelopes.push_back(
        envelope);
}

QVector<MessageEnvelope>
LocalMessageStore::envelopes() const
{
    return m_envelopes;
}

QVector<MessageEnvelope>
LocalMessageStore::envelopesForConversation(
    const QString& conversationId) const
{
    QVector<MessageEnvelope> results;

    for (const auto& envelope :
         m_envelopes) {

        if (envelope.conversationId ==
            conversationId) {

            results.push_back(
                envelope);
        }
    }

    return results;
}

void LocalMessageStore::storeDecryptedMessage(
    const DecryptedMessage& message)
{
    if (message.id.isEmpty()) {
        return;
    }

    // Deduplicate by message ID.
    if (m_messageIndex.contains(
            message.id)) {

        return;
    }

    const int index =
        m_decryptedMessages.size();

    m_messageIndex.insert(
        message.id,
        index);

    m_decryptedMessages.push_back(
        message);
}

QVector<DecryptedMessage>
LocalMessageStore::decryptedMessages()
    const
{
    return m_decryptedMessages;
}

QVector<DecryptedMessage>
LocalMessageStore::messagesForConversation(
    const QString& conversationId)
    const
{
    QVector<DecryptedMessage>
        results;

    for (const auto& message :
         m_decryptedMessages) {

        if (message.conversationId ==
            conversationId) {

            results.push_back(
                message);
        }
    }

    return results;
}

bool LocalMessageStore::containsMessage(
    const QString& messageId)
    const
{
    return m_messageIndex.contains(
        messageId);
}

void LocalMessageStore::clearConversation(
    const QString& conversationId)
{
    QVector<DecryptedMessage>
        retainedMessages;

    m_messageIndex.clear();

    for (const auto& message :
         m_decryptedMessages) {

        if (message.conversationId !=
            conversationId) {

            retainedMessages.push_back(
                message);
        }
    }

    m_decryptedMessages =
        retainedMessages;

    for (int i = 0;
         i < m_decryptedMessages.size();
         ++i) {

        m_messageIndex.insert(
            m_decryptedMessages[i].id,
            i);
    }

    QVector<MessageEnvelope>
        retainedEnvelopes;

    for (const auto& envelope :
         m_envelopes) {

        if (envelope.conversationId !=
            conversationId) {

            retainedEnvelopes.push_back(
                envelope);
        }
    }

    m_envelopes =
        retainedEnvelopes;
}

void LocalMessageStore::clearAll()
{
    m_envelopes.clear();

    m_decryptedMessages.clear();

    m_messageIndex.clear();
}
