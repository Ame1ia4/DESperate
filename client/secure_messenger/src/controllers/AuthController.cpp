#include "AuthController.h"

#include "src/storage/SessionStore.h"
#include "src/storage/TrustStore.h"
#include "src/services/ApiClient.h"
#include "src/services/CryptoServiceClient.h"

#include <QDebug>
#include <QJsonDocument>
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

    m_loginInProgress = true;
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

                m_loginInProgress = false;

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

            m_loginInProgress = false;

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

            m_loginInProgress = false;

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

    qDebug() << "[REGISTRATION] signUp called"
             << "| username:" << normalized
             << "| passwordLen:" << password.length();

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

    qDebug() << "[REGISTRATION] Step 1: fetching nonce from server";

    // Step 1: fetch a single-use nonce from the server for proof-of-possession.
    auto nonceSuccessConn = std::make_shared<QMetaObject::Connection>();
    auto nonceFailConn    = std::make_shared<QMetaObject::Connection>();

    *nonceSuccessConn = connect(
        m_api,
        &ApiClient::fetchRegistrationNonceSucceeded,
        this,
        [this, normalized, password, nonceFailConn](const QString& nonce) {

            QObject::disconnect(*nonceFailConn);

            qDebug() << "[REGISTRATION] Step 1 OK: nonce received";

            qDebug() << "[REGISTRATION] Step 2: calling generateIdentityBundle";

            // Step 2: generate all key material including SRP verifier (sync RPC).
            const QJsonObject bundle =
                m_crypto->generateIdentityBundle(normalized, password, nonce);

            if (bundle.isEmpty()) {
                const QString reason =
                    m_crypto->lastError().isEmpty()
                        ? "Key generation failed."
                        : m_crypto->lastError();
                qDebug() << "[REGISTRATION] Step 2 FAILED: bundle empty | error:" << reason;
                setAuthError(reason);
                emit registrationFailed(reason);
                return;
            }

            qDebug() << "[REGISTRATION] Step 2 OK: bundle generated";

            qDebug() << "[REGISTRATION] Step 3: calling registerUser (POST /auth/register)";

            // Step 3: register with the server.
            auto regSuccessConn = std::make_shared<QMetaObject::Connection>();
            auto regFailConn    = std::make_shared<QMetaObject::Connection>();

            *regSuccessConn = connect(
                m_api,
                &ApiClient::registerUserSucceeded,
                this,
                [this, normalized, regFailConn](const QString& deviceId) {

                    QObject::disconnect(*regFailConn);

                    qDebug() << "[REGISTRATION] Step 3 OK: registered | deviceId:" << deviceId;

                    m_api->storeDeviceId(normalized, deviceId);

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

                    qDebug() << "[REGISTRATION] Step 3 FAILED: server rejected registration | reason:" << reason;

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

            qDebug() << "[REGISTRATION] Step 1 FAILED: nonce fetch failed | reason:" << reason;

            const QString failureReason =
                reason.isEmpty() ? "Registration failed." : reason;
            setAuthError(failureReason);
            emit registrationFailed(failureReason);
        },
        Qt::SingleShotConnection);

    m_api->fetchRegistrationNonce();
}

void AuthController::changePassword(
    const QString& currentPassword,
    const QString& newPassword,
    const QString& confirmPassword)
{
    if (currentPassword.isEmpty()) {
        emit changePasswordFailed(QStringLiteral("Current password is required."));
        return;
    }

    if (newPassword.isEmpty()) {
        emit changePasswordFailed(QStringLiteral("New password is required."));
        return;
    }

    if (newPassword != confirmPassword) {
        emit changePasswordFailed(QStringLiteral("Passwords do not match."));
        return;
    }

    const QJsonObject result =
        m_crypto->preparePasswordChange(m_currentUserId, currentPassword, newPassword);

    if (result.isEmpty() || result.contains(QStringLiteral("error"))) {
        emit changePasswordFailed(
            result.value(QStringLiteral("error"))
                .toString(QStringLiteral("Failed to prepare password change.")));
        return;
    }

    const QString newSalt     = result.value(QStringLiteral("new_salt")).toString();
    const QString newVerifier = result.value(QStringLiteral("new_verifier")).toString();

    auto successConn = std::make_shared<QMetaObject::Connection>();
    auto failConn    = std::make_shared<QMetaObject::Connection>();

    *successConn = connect(
        m_api,
        &ApiClient::changePasswordSucceeded,
        this,
        [this, failConn]() {
            QObject::disconnect(*failConn);
            m_crypto->commitPasswordChange();
            logout();
            emit changePasswordSucceeded();
        },
        Qt::SingleShotConnection);

    *failConn = connect(
        m_api,
        &ApiClient::changePasswordFailed,
        this,
        [this, successConn](const QString& reason) {
            QObject::disconnect(*successConn);
            emit changePasswordFailed(
                reason.isEmpty()
                    ? QStringLiteral("Password change failed.")
                    : reason);
        },
        Qt::SingleShotConnection);

    m_api->changePassword(newSalt, newVerifier);
}

void AuthController::logout()
{
    if (m_authenticated) {
        m_authenticated = false;
        emit authenticatedChanged();
    }

    // Zero out all session credentials immediately so no in-flight request
    // after this point can be signed with the previous user's token or HMAC key.
    m_api->clearCredentials();

    m_currentUserId.clear();
    emit currentUserChanged();
    setAuthError(QString());
}