#include "AuthController.h"
#include "services/ApiClient.h"
#include "services/CryptoServiceClient.h"

AuthController::AuthController(
    ApiClient* api,
    CryptoServiceClient* crypto,
    TrustStore* trust,
    QObject* parent
    )
    : QObject(parent)
    , m_api(api)
    , m_crypto(crypto)
    , m_trust(trust)
{
}

bool AuthController::authenticated() const
{
    return m_authenticated;
}

void AuthController::unlock(
    const QString& username,
    const QString& password
    )
{
    bool unlocked = m_crypto->unlockKeystore(password);

    if (!unlocked)
    {
        emit loginFailed("Invalid password");
        return;
    }

    m_authenticated = true;

    emit authenticatedChanged();
    emit loginSucceeded();
}

void AuthController::registerDevice(
    const QString& username,
    const QString& password
    )
{
    auto bundle = m_crypto->generateIdentityBundle(password);

    m_api->registerUser(
        username,
        bundle
        );
}