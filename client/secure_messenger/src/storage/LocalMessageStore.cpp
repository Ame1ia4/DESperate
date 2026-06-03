
#include "LocalMessageStore.h"

#include <QDateTime>
#include <QSettings>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>

    LocalMessageStore::LocalMessageStore(
        QObject* parent)
    : QObject(parent)
{
        // Load persisted messages and envelopes (if any)
        QSettings settings;

        const QByteArray decryptedJson = settings.value("local_store/decryptedMessages").toByteArray();
        if (!decryptedJson.isEmpty()) {
            const auto doc = QJsonDocument::fromJson(decryptedJson);
            if (doc.isArray()) {
                const QJsonArray arr = doc.array();
                for (const auto& v : arr) {
                    if (!v.isObject()) continue;
                    const auto obj = v.toObject();
                    DecryptedMessage m;
                    m.id = obj.value("id").toString();
                    m.conversationId = obj.value("conversationId").toString();
                    m.senderDeviceId = obj.value("senderDeviceId").toString();
                    m.plaintext = obj.value("plaintext").toString();
                    m.timestamp = QDateTime::fromString(obj.value("timestamp").toString(), Qt::ISODateWithMs);
                    m.verificationState = static_cast<VerificationState>(obj.value("verificationState").toInt(0));
                    m.isDeleted = obj.value("isDeleted").toBool(false);
                    m.revoked  = obj.value("revoked").toBool(false);
                    const int index = m_decryptedMessages.size();
                    m_messageIndex.insert(m.id, index);
                    m_decryptedMessages.push_back(m);
                }
            }
        }

        const QByteArray envelopesJson = settings.value("local_store/envelopes").toByteArray();
        if (!envelopesJson.isEmpty()) {
            const auto doc = QJsonDocument::fromJson(envelopesJson);
            if (doc.isArray()) {
                const QJsonArray arr = doc.array();
                for (const auto& v : arr) {
                    if (!v.isObject()) continue;
                    const auto obj = v.toObject();
                    MessageEnvelope e;
                    e.id = obj.value("id").toString();
                    e.conversationId = obj.value("conversationId").toString();
                    e.senderDeviceId = obj.value("senderDeviceId").toString();
                    e.ciphertext = QByteArray::fromBase64(obj.value("ciphertext").toString().toUtf8());
                    e.nonce = QByteArray::fromBase64(obj.value("nonce").toString().toUtf8());
                    e.associatedData = QByteArray::fromBase64(obj.value("associatedData").toString().toUtf8());
                    e.txHash = obj.value("txHash").toString();
                    e.merkleRoot = obj.value("merkleRoot").toString();
                    e.timestamp = QDateTime::fromString(obj.value("timestamp").toString(), Qt::ISODateWithMs);
                    e.verificationState = static_cast<VerificationState>(obj.value("verificationState").toInt(0));
                    e.isDeleted = obj.value("isDeleted").toBool(false);
                    m_envelopes.push_back(e);
                }
            }
        }
}

    static QJsonObject decryptedMessageToJson(const DecryptedMessage& m) {
        QJsonObject obj;
        obj["id"] = m.id;
        obj["conversationId"] = m.conversationId;
        obj["senderDeviceId"] = m.senderDeviceId;
        obj["plaintext"] = m.plaintext;
        obj["timestamp"] = m.timestamp.toString(Qt::ISODateWithMs);
        obj["verificationState"] = static_cast<int>(m.verificationState);
        obj["isDeleted"] = m.isDeleted;
        obj["revoked"] = m.revoked;
        return obj;
    }

    static QJsonObject envelopeToJson(const MessageEnvelope& e) {
        QJsonObject obj;
        obj["id"] = e.id;
        obj["conversationId"] = e.conversationId;
        obj["senderDeviceId"] = e.senderDeviceId;
        obj["ciphertext"] = QString::fromLatin1(e.ciphertext.toBase64());
        obj["nonce"] = QString::fromLatin1(e.nonce.toBase64());
        obj["associatedData"] = QString::fromLatin1(e.associatedData.toBase64());
        obj["txHash"] = e.txHash;
        obj["merkleRoot"] = e.merkleRoot;
        obj["timestamp"] = e.timestamp.toString(Qt::ISODateWithMs);
        obj["verificationState"] = static_cast<int>(e.verificationState);
        obj["isDeleted"] = e.isDeleted;
        return obj;
    }

    void LocalMessageStore::saveState() const {
        QSettings settings;

        QJsonArray decArr;
        for (const auto& m : m_decryptedMessages) decArr.push_back(decryptedMessageToJson(m));
        settings.setValue("local_store/decryptedMessages", QJsonDocument(decArr).toJson());

        QJsonArray envArr;
        for (const auto& e : m_envelopes) envArr.push_back(envelopeToJson(e));
        settings.setValue("local_store/envelopes", QJsonDocument(envArr).toJson());
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
        QByteArray::fromHex(
            envelope.value(
                        "ciphertext")
                .toString()
                .toUtf8());

    typedEnvelope.nonce =
        QByteArray::fromHex(
            envelope.value(
                        "nonce")
                .toString()
                .toUtf8());

    typedEnvelope.associatedData =
        QByteArray::fromHex(
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

    saveState();
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

    saveState();
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

QByteArray LocalMessageStore::ciphertextForMessage(
    const QString& messageId)
    const
{
    for (const auto& e : m_envelopes) {
        if (e.id == messageId)
            return e.ciphertext;
    }
    return {};
}

void LocalMessageStore::updateMessageId(
    const QString& oldId,
    const QString& newId)
{
    if (oldId.isEmpty() || newId.isEmpty() || oldId == newId) return;

    if (m_messageIndex.contains(oldId)) {
        const int idx = m_messageIndex.take(oldId);
        m_messageIndex.insert(newId, idx);
        m_decryptedMessages[idx].id = newId;
    }

    for (auto& e : m_envelopes) {
        if (e.id == oldId) {
            e.id = newId;
            break;
        }
    }

    saveState();
}

void LocalMessageStore::removeDecryptedMessage(const QString& messageId)
{
    if (!m_messageIndex.contains(messageId)) return;

    const int idx = m_messageIndex.value(messageId);
    m_decryptedMessages.removeAt(idx);

    // Positions after the removed row shifted — rebuild the whole index.
    m_messageIndex.clear();
    for (int i = 0; i < m_decryptedMessages.size(); ++i)
        m_messageIndex.insert(m_decryptedMessages[i].id, i);

    saveState();
}

void LocalMessageStore::markMessageRevoked(const QString& messageId)
{
    if (!m_messageIndex.contains(messageId)) return;
    auto& msg = m_decryptedMessages[m_messageIndex.value(messageId)];
    if (msg.revoked) return;
    msg.revoked = true;
    saveState();
}

void LocalMessageStore::markMessageDeleted(const QString& messageId)
{
    if (!m_messageIndex.contains(messageId)) return;
    auto& msg = m_decryptedMessages[m_messageIndex.value(messageId)];
    if (msg.isDeleted) return;
    msg.isDeleted = true;
    saveState();
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

    saveState();
}

void LocalMessageStore::clearAll()
{
    m_envelopes.clear();

    m_decryptedMessages.clear();

    m_messageIndex.clear();
    saveState();
}
