#pragma once

#include <QObject>
#include <QNetworkAccessManager>
#include <QJsonObject>
#include <QJsonArray>
#include <QSettings>

class CryptoServiceClient;

class ApiClient : public QObject
{
    Q_OBJECT

public:
    explicit ApiClient(CryptoServiceClient* crypto, QObject* parent = nullptr);

    void registerUser(
        const QString& username,
        const QJsonObject& bundle
        );

    void loginUser(
        const QString& username,
        const QString& password
        );

    void fetchRegistrationNonce();

    void sendMessage(
        const QJsonObject& encryptedEnvelope
        );

    void pullMessages(
        const QString& deviceId
        );

    void acknowledgeMessage(
        const QString& messageId,
        const QString& deviceId
        );

    void setAuthToken(const QString& token);

    void fetchConversations();

    QString storedDeviceId() const;
    void    storeDeviceId(const QString& deviceId);

signals:
    void registerUserSucceeded(QString deviceId);
    void registerUserFailed(QString reason);
    void loginUserSucceeded();
    void loginUserFailed(QString reason);
    void fetchRegistrationNonceSucceeded(QString nonce);
    void fetchRegistrationNonceFailed(QString reason);
    void fetchConversationsSucceeded(QJsonArray conversations);
    void fetchConversationsFailed(QString reason);
    void pullMessagesSucceeded(QJsonArray envelopes);
    void pullMessagesFailed();
    void acknowledgeMessageSucceeded(QString messageId);
    void acknowledgeMessageFailed(QString messageId);

private:
    void doSrpInit(
        const QString& username,
        const QString& deviceId,
        const QString& A);

    void doSrpVerify(
        const QString& username,
        const QString& deviceId,
        const QString& A,
        const QString& M1);

    QNetworkAccessManager m_network;
    CryptoServiceClient*  m_crypto = nullptr;
    QString               m_authToken;
    QSettings             m_settings;

    QNetworkRequest makeRequest(
        const QString& path
        );
};