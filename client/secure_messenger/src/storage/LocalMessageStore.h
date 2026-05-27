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

    std::vector<MessageEnvelope> envelopes() const;

private:
    std::vector<MessageEnvelope> m_envelopes;
};
