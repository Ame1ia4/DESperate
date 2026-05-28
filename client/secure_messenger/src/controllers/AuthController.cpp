#include "AuthController.h"
#include "src/services/ApiClient.h"
#include "src/services/CryptoServiceClient.h"

namespace {
constexpr const char* DEMO_USERNAME = "demo";
constexpr const char* DEMO_PASSWORD = "demo123";
}

AuthController::AuthController(
    ApiClient* api,
    CryptoServiceClient* crypto,
    QObject* parent
    )
    : QObject(parent)
    , m_api(api)
    , m_crypto(crypto)
{
}

bool AuthController::authenticated() const
{
    return m_authenticated;
}

QString AuthController::authError() const
{
    return m_authError;
}

void AuthController::login(
    const QString& username,
    const QString& password
    )
{
    const QString normalizedUsername = username.trimmed();
    if (normalizedUsername.isEmpty() || password.isEmpty()) {
        m_authError = "Username and password are required.";
        emit authErrorChanged();
        emit loginFailed(m_authError);
        return;
    }

    if (normalizedUsername == DEMO_USERNAME && password == DEMO_PASSWORD) {
        m_authError.clear();
        emit authErrorChanged();

        if (!m_authenticated) {
            m_authenticated = true;
            emit authenticatedChanged();
        }

        emit loginSucceeded();
        return;
    }

    connect(
        m_api,
        &ApiClient::loginUserSucceeded,
        this,
        [this, password]() {
            if (!m_crypto->unlockKeystore(password)) {
                m_authError = m_crypto->lastError();
                if (m_authError.isEmpty()) {
                    m_authError = "Authentication failed.";
                }
                emit authErrorChanged();
                emit loginFailed(m_authError);
                return;
            }

            m_authError.clear();
            emit authErrorChanged();

            if (!m_authenticated) {
                m_authenticated = true;
                emit authenticatedChanged();
            }
            emit loginSucceeded();
        },
        Qt::SingleShotConnection
        );

    connect(
        m_api,
        &ApiClient::loginUserFailed,
        this,
        [this](const QString& reason) {
            m_authError = reason.isEmpty()
                ? "No matching credentials found."
                : reason;
            emit authErrorChanged();
            emit loginFailed(m_authError);
        },
        Qt::SingleShotConnection
        );

    m_api->loginUser(normalizedUsername, password);
}

void AuthController::signUp(
    const QString& username,
    const QString& password,
    const QString& confirmPassword
    )
{
    const QString normalizedUsername = username.trimmed();
    if (normalizedUsername.isEmpty() || password.isEmpty()) {
        m_authError = "Username and password are required.";
        emit authErrorChanged();
        emit registrationFailed(m_authError);
        return;
    }

    if (password != confirmPassword) {
        m_authError = "Passwords do not match.";
        emit authErrorChanged();
        emit registrationFailed(m_authError);
        return;
    }

    m_authError = "Registration is unavailable in demo mode. Use demo/demo123 to login.";
    emit authErrorChanged();
    emit registrationFailed(m_authError);
}

void AuthController::logout()
{
    if (m_authenticated) {
        m_authenticated = false;
        emit authenticatedChanged();
    }

    m_authError.clear();
    emit authErrorChanged();
}