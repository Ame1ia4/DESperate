#pragma once

#include <QObject>

class ApiClient;
class CryptoServiceClient;
class TrustStore;

class AuthController : public QObject
{
    Q_OBJECT

    Q_PROPERTY(bool authenticated
                   READ authenticated
                       NOTIFY authenticatedChanged)

public:
    explicit AuthController(
        ApiClient* api,
        CryptoServiceClient* crypto,
        TrustStore* trust,
        QObject* parent = nullptr
        );

    Q_INVOKABLE void unlock(
        const QString& username,
        const QString& password
        );

    Q_INVOKABLE void registerDevice(
        const QString& username,
        const QString& password
        );

    bool authenticated() const;

signals:
    void authenticatedChanged();
    void loginFailed(QString reason);
    void loginSucceeded();

private:
    bool m_authenticated = false;

    ApiClient* m_api;
    CryptoServiceClient* m_crypto;
    TrustStore* m_trust;
};