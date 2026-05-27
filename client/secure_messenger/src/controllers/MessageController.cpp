#include "MessageController.h"

#include "services/ApiClient.h"
#include "services/CryptoServiceClient.h"
#include "storage/LocalMessageStore.h"
#include "models/MessageModel.h"
#include "types/Types.h"

#include <algorithm>
#include <QDateTime>

namespace {
void wipeQStringBestEffort(QString& value)
{
    if (value.isNull()) {
        return;
    }

    auto* chars = value.data();
    std::fill(chars, chars + value.size(), QChar(u'\0'));
    value.clear();
}
}

MessageController::MessageController(
    ApiClient* api,
    CryptoServiceClient* crypto,
    LocalMessageStore* store,
    MessageModel* model,
    TrustStore* trust,
    QObject* parent
    )
    : QObject(parent)
    , m_api(api)
    , m_crypto(crypto)
    , m_store(store)
    , m_model(model)
    , m_trust(trust)
{
}

void MessageController::sendMessage(
    QString conversationId,
    QString recipientDeviceId,
    QString plaintext
    )
{
    connect(
        m_crypto,
        &CryptoServiceClient::encryptCompleted,
        this,
        [this](const QJsonObject& envelope) {
            m_store->storeOutgoingMessage(envelope);
            m_api->sendMessage(envelope);
            emit messageSent();
        },
        Qt::SingleShotConnection
        );

    connect(
        m_crypto,
        &CryptoServiceClient::encryptFailed,
        this,
        [this](const QString&) {
            emit messageSendFailed("Message send failed.");
        },
        Qt::SingleShotConnection
        );

    m_crypto->encryptMessageAsync(
        plaintext,
        recipientDeviceId,
        conversationId
        );

    wipeQStringBestEffort(plaintext);
}

void MessageController::receiveEnvelope(
    QJsonObject envelope
    )
{
    connect(
        m_crypto,
        &CryptoServiceClient::decryptCompleted,
        this,
        [this, envelope](const QString& plaintext) {
            DecryptedMessage message;
            message.id = envelope.value("id").toString();
            message.conversationId =
                envelope.value("conversation_id").toString();
            message.senderDeviceId =
                envelope.value("sender_device_id").toString();
            message.timestamp = QDateTime::currentDateTimeUtc();
            message.plaintext = plaintext;

            m_model->addMessage(message);
            // ACK path to purge server queue will be added with pull/queue API.
            emit messageReceived();
        },
        Qt::SingleShotConnection
        );

    connect(
        m_crypto,
        &CryptoServiceClient::decryptFailed,
        this,
        [this](const QString&) {
            emit messageReceiveFailed("Message receive failed.");
        },
        Qt::SingleShotConnection
        );

    m_crypto->decryptMessageAsync(envelope);
}