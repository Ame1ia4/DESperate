#pragma once

#include <QObject>

class ApiClient;
class CryptoServiceClient;

class AuthController : public QObject
{
    Q_OBJECT

    Q_PROPERTY(bool authenticated
                   READ authenticated
                       NOTIFY authenticatedChanged)
    Q_PROPERTY(QString authError
                   READ authError
                       NOTIFY authErrorChanged)

public:
    explicit AuthController(
        ApiClient* api,
        CryptoServiceClient* crypto,
        QObject* parent = nullptr
        );

    Q_INVOKABLE void login(
        const QString& username,
        const QString& password
        );

    Q_INVOKABLE void signUp(
        const QString& username,
        const QString& password,
        const QString& confirmPassword
        );
    Q_INVOKABLE void logout();

    bool authenticated() const;
    QString authError() const;

signals:
    void authenticatedChanged();
    void authErrorChanged();
    void loginFailed(QString reason);
    void loginSucceeded();
    void registrationFailed(QString reason);
    void registrationSucceeded();

private:
    bool m_authenticated = false;
    QString m_authError;

    ApiClient* m_api;
    CryptoServiceClient* m_crypto;
};