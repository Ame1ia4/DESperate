#include "AuthController.h"

#include "src/storage/SessionStore.h"
#include "src/storage/TrustStore.h"
#include "src/services/ApiClient.h"
#include "src/services/CryptoServiceClient.h"

#include <memory>

AuthController::AuthController(
    ApiClient* api,
    CryptoServiceClient* crypto,
    TrustStore* trust,
    SessionStore* sessions,
    QObject* parent)
    : QObject(parent)
    , m_api(api)
    , m_crypto(crypto)
    , m_trust(trust)
    , m_sessions(sessions)
{
}

bool AuthController::authenticated() const noexcept
{
    return m_authenticated;
}

QString AuthController::authError() const
{
    return m_authError;
}

QString AuthController::currentUserId() const
{
    return m_currentUserId;
}

void AuthController::setAuthError(
    const QString& error)
{
    if (m_authError == error) {
        return;
    }

    m_authError = error;

    emit authErrorChanged();
}

void AuthController::login(
    const QString& username,
    const QString& password)
{
    const QString normalized =
        username.trimmed();

    if (normalized.isEmpty() ||
        password.isEmpty()) {

        setAuthError(
            "Username and password are required.");

        emit loginFailed(m_authError);

        return;
    }

    // Use shared connection handles so each lambda can disconnect the
    // other.  Qt::SingleShotConnection only disconnects the connection
    // whose signal fired; without this, the unused handler would leak
    // and accumulate on repeated login attempts.
    auto successConn = std::make_shared<QMetaObject::Connection>();
    auto failConn    = std::make_shared<QMetaObject::Connection>();

    *successConn = connect(
        m_api,
        &ApiClient::loginUserSucceeded,
        this,
        [this, normalized, password, failConn]() {

            QObject::disconnect(*failConn);

            if (!m_crypto->unlockKeystore(password)) {

                QString reason =
                    m_crypto->lastError();

                if (reason.isEmpty()) {
                    reason =
                        "Failed to unlock keystore.";
                }

                setAuthError(reason);

                emit loginFailed(reason);

                return;
            }

            emit keystoreUnlocked();

            m_currentUserId = normalized;
            emit currentUserChanged();

            emit identityLoaded();
            emit sessionInitialized();

            setAuthError(QString());

            if (!m_authenticated) {
                m_authenticated = true;
                emit authenticatedChanged();
            }

            emit loginSucceeded();
        },
        Qt::SingleShotConnection);

    *failConn = connect(
        m_api,
        &ApiClient::loginUserFailed,
        this,
        [this, successConn](const QString& reason) {

            QObject::disconnect(*successConn);

            const QString failureReason =
                reason.isEmpty()
                    ? "Authentication failed."
                    : reason;

            setAuthError(failureReason);

            emit loginFailed(failureReason);
        },
        Qt::SingleShotConnection);

    m_api->loginUser(normalized, password);
}

void AuthController::signUp(
    const QString& username,
    const QString& password,
    const QString& confirmPassword)
{
    const QString normalized = username.trimmed();

    if (normalized.isEmpty() || password.isEmpty()) {
        setAuthError("Username and password are required.");
        emit registrationFailed(m_authError);
        return;
    }

    if (password != confirmPassword) {
        setAuthError("Passwords do not match.");
        emit registrationFailed(m_authError);
        return;
    }

    // Step 1: fetch a single-use nonce from the server for proof-of-possession.
    auto nonceSuccessConn = std::make_shared<QMetaObject::Connection>();
    auto nonceFailConn    = std::make_shared<QMetaObject::Connection>();

    *nonceSuccessConn = connect(
        m_api,
        &ApiClient::fetchRegistrationNonceSucceeded,
        this,
        [this, normalized, password, nonceFailConn](const QString& nonce) {

            QObject::disconnect(*nonceFailConn);

            // Step 2: generate all key material including SRP verifier (sync RPC).
            const QJsonObject bundle =
                m_crypto->generateIdentityBundle(normalized, password, nonce);

            if (bundle.isEmpty()) {
                const QString reason =
                    m_crypto->lastError().isEmpty()
                        ? "Key generation failed."
                        : m_crypto->lastError();
                setAuthError(reason);
                emit registrationFailed(reason);
                return;
            }

            // Step 3: register with the server.
            auto regSuccessConn = std::make_shared<QMetaObject::Connection>();
            auto regFailConn    = std::make_shared<QMetaObject::Connection>();

            *regSuccessConn = connect(
                m_api,
                &ApiClient::registerUserSucceeded,
                this,
                [this, regFailConn](const QString& deviceId) {

                    QObject::disconnect(*regFailConn);

                    // Persist device ID for subsequent logins.
                    m_api->storeDeviceId(deviceId);

                    setAuthError(QString());
                    emit registrationSucceeded();
                },
                Qt::SingleShotConnection);

            *regFailConn = connect(
                m_api,
                &ApiClient::registerUserFailed,
                this,
                [this, regSuccessConn](const QString& reason) {

                    QObject::disconnect(*regSuccessConn);

                    const QString failureReason =
                        reason.isEmpty() ? "Registration failed." : reason;
                    setAuthError(failureReason);
                    emit registrationFailed(failureReason);
                },
                Qt::SingleShotConnection);

            m_api->registerUser(normalized, bundle);
        },
        Qt::SingleShotConnection);

    *nonceFailConn = connect(
        m_api,
        &ApiClient::fetchRegistrationNonceFailed,
        this,
        [this, nonceSuccessConn](const QString& reason) {

            QObject::disconnect(*nonceSuccessConn);

            const QString failureReason =
                reason.isEmpty() ? "Registration failed." : reason;
            setAuthError(failureReason);
            emit registrationFailed(failureReason);
        },
        Qt::SingleShotConnection);

    m_api->fetchRegistrationNonce();
}

void AuthController::logout()
{
    if (m_authenticated) {
        m_authenticated = false;

        emit authenticatedChanged();
    }

    m_currentUserId.clear();

    emit currentUserChanged();

    setAuthError(QString());
}