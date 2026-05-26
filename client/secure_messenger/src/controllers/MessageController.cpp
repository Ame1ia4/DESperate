#include "MessageController.h"

#include "services/ApiClient.h"
#include "services/CryptoServiceClient.h"
#include "services/LocalMessageStore.h"

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
    auto envelope = m_crypto->encryptMessage(
        plaintext,
        recipientDeviceId,
        conversationId
        );

    m_store->storeOutgoingMessage(envelope);

    m_api->sendMessage(envelope);
}