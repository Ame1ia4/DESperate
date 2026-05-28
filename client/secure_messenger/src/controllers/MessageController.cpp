#include "MessageController.h"

#include "services/ApiClient.h"
#include "services/CryptoServiceClient.h"
#include "storage/LocalMessageStore.h"
#include "models/MessageModel.h"
#include "types/Types.h"

#include <QJsonArray>
#include <QDateTime>

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
    // Plaintext is copied into encryptMessageAsync before this returns; QString
    // implicit sharing means caller-side wiping would not clear other copies.
    // Real protection belongs at the crypto-service process boundary.

    // Concurrent sends share one CryptoServiceClient. SingleShotConnection
    // pairs one callback per call, but overlapping operations can still
    // interleave; request IDs or per-call task objects are needed for isolation.

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
            const auto senderTimestamp = QDateTime::fromString(
                envelope.value("created_at").toString(),
                Qt::ISODateWithMs
                );

            DecryptedMessage message;
            message.id = envelope.value("id").toString();
            message.conversationId =
                envelope.value("conversation_id").toString();
            message.senderDeviceId =
                envelope.value("sender_device_id").toString();
            message.timestamp = senderTimestamp.isValid()
                ? senderTimestamp
                : QDateTime::currentDateTimeUtc();
            message.plaintext = plaintext;

            m_store->storeDecryptedMessage(message);
            m_model->addMessage(message);
            m_api->acknowledgeMessage(
                message.id,
                envelope.value("recipient_device_id").toString()
                );
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

void MessageController::pullAndProcessMessages(
    QString deviceId
    )
{
    connect(
        m_api,
        &ApiClient::pullMessagesSucceeded,
        this,
        [this](const QJsonArray& envelopes) {
            for (const auto& envelopeValue : envelopes) {
                const auto envelope = envelopeValue.toObject();
                if (!envelope.isEmpty()) {
                    receiveEnvelope(envelope);
                }
            }
        },
        Qt::SingleShotConnection
        );

    connect(
        m_api,
        &ApiClient::pullMessagesFailed,
        this,
        [this]() {
            emit messageReceiveFailed("Message receive failed.");
        },
        Qt::SingleShotConnection
        );

    m_api->pullMessages(deviceId);
}