#pragma once

#include <QObject>
#include <QString>

    class ApiClient;
class CryptoServiceClient;
class TrustStore;
class SessionStore;

class AuthController : public QObject
{
    Q_OBJECT

    Q_PROPERTY(bool authenticated
                   READ authenticated
                       NOTIFY authenticatedChanged)

    Q_PROPERTY(QString authError
                   READ authError
                       NOTIFY authErrorChanged)

    Q_PROPERTY(QString currentUserId
                   READ currentUserId
                       NOTIFY currentUserChanged)

public:
    explicit AuthController(
        ApiClient* api,
        CryptoServiceClient* crypto,
        TrustStore* trust,
        SessionStore* sessions,
        QObject* parent = nullptr);

    bool authenticated() const noexcept;

    QString authError() const;

    QString currentUserId() const;

public slots:
    void login(
        const QString& username,
        const QString& password);

    void signUp(
        const QString& username,
        const QString& password,
        const QString& confirmPassword);

    void logout();

signals:
    void authenticatedChanged();

    void authErrorChanged();

    void currentUserChanged();

    void loginSucceeded();

    void loginFailed(QString reason);

    void registrationSucceeded();

    void registrationFailed(QString reason);

    void keystoreUnlocked();

    void identityLoaded();

    void sessionInitialized();

private:
    void setAuthError(const QString& error);

private:
    ApiClient* m_api = nullptr;

    CryptoServiceClient* m_crypto = nullptr;

    TrustStore* m_trust = nullptr;

    SessionStore* m_sessions = nullptr;

    bool m_authenticated = false;

    QString m_authError;

    QString m_currentUserId;

    bool m_loginInProgress = false;
};
