#include "LocalMessageStore.h"

LocalMessageStore::LocalMessageStore(QObject* parent)
    : QObject(parent)
{
}

void LocalMessageStore::storeOutgoingMessage(
    const QJsonObject& envelope
    )
{
    MessageEnvelope typedEnvelope;
    typedEnvelope.id = envelope.value("id").toString();
    typedEnvelope.conversationId =
        envelope.value("conversation_id").toString();
    typedEnvelope.senderDeviceId =
        envelope.value("sender_device_id").toString();
    typedEnvelope.ciphertext = QByteArray::fromBase64(
        envelope.value("ciphertext").toString().toUtf8()
        );
    typedEnvelope.nonce = QByteArray::fromBase64(
        envelope.value("nonce").toString().toUtf8()
        );
    typedEnvelope.associatedData = QByteArray::fromBase64(
        envelope.value("associated_data").toString().toUtf8()
        );
    typedEnvelope.txHash = envelope.value("tx_hash").toString();
    typedEnvelope.merkleRoot = envelope.value("merkle_root").toString();
    typedEnvelope.timestamp = QDateTime::currentDateTimeUtc();

    storeOutgoingEnvelope(typedEnvelope);
}

void LocalMessageStore::storeOutgoingEnvelope(
    const MessageEnvelope& envelope
    )
{
    // Intentionally stores only envelope data; plaintext is never persisted.
    m_envelopes.push_back(envelope);
}

std::vector<MessageEnvelope> LocalMessageStore::envelopes() const
{
    return m_envelopes;
}
