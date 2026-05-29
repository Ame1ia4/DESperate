#include "AuthController.h"

#include "src/storage/SessionStore.h"
#include "src/storage/TrustStore.h"
#include "src/services/ApiClient.h"
#include "src/services/CryptoServiceClient.h"

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

    connect(
        m_api,
        &ApiClient::loginUserSucceeded,
        this,
        [this, normalized, password]() {

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

    connect(
        m_api,
        &ApiClient::loginUserFailed,
        this,
        [this](const QString& reason) {

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
    const QString normalized =
        username.trimmed();

    if (normalized.isEmpty() ||
        password.isEmpty()) {

        setAuthError(
            "Username and password are required.");

        emit registrationFailed(m_authError);

        return;
    }

    if (password != confirmPassword) {

        setAuthError(
            "Passwords do not match.");

        emit registrationFailed(m_authError);

        return;
    }

    const QJsonObject bundle =
        m_crypto->generateIdentityBundle(
            password);

    if (bundle.isEmpty()) {

        const QString reason =
            m_crypto->lastError().isEmpty()
                ? "Key generation failed."
                : m_crypto->lastError();

        setAuthError(reason);

        emit registrationFailed(reason);

        return;
    }

    connect(
        m_api,
        &ApiClient::registerUserSucceeded,
        this,
        [this]() {

            setAuthError(QString());

            emit registrationSucceeded();
        },
        Qt::SingleShotConnection);

    connect(
        m_api,
        &ApiClient::registerUserFailed,
        this,
        [this](const QString& reason) {

            const QString failureReason =
                reason.isEmpty()
                    ? "Registration failed."
                    : reason;

            setAuthError(failureReason);

            emit registrationFailed(
                failureReason);
        },
        Qt::SingleShotConnection);

    m_api->registerUser(normalized, bundle);
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