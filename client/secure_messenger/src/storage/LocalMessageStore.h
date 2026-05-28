#pragma once

#include <QObject>
#include <QJsonObject>
#include <vector>

#include "../types/Types.h"

class LocalMessageStore : public QObject
{
    Q_OBJECT

public:
    explicit LocalMessageStore(QObject* parent = nullptr);

    void storeOutgoingMessage(const QJsonObject& envelope);
    void storeOutgoingEnvelope(const MessageEnvelope& envelope);
    void storeDecryptedMessage(const DecryptedMessage& message);

    std::vector<MessageEnvelope> envelopes() const;
    std::vector<DecryptedMessage> decryptedMessages() const;

private:
    std::vector<MessageEnvelope> m_envelopes;
    std::vector<DecryptedMessage> m_decryptedMessages;
};
