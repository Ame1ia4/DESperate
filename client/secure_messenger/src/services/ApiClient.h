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
    void fetchConversationMessages(const QString& conversationId);

    // Fetch the public PQXDH key bundle for a username (GET /keys/:username).
    void fetchKeyBundle(const QString& username);
    void deleteMessage(const QString& messageId);
    void revokeMessage(const QString& messageId, const QString& recipientDeviceId);

    //meaningless change
    // Create a new conversation with another user (POST /conversations).
    void createConversation(const QString& otherUsername);

    QString storedDeviceId(const QString& username) const;
    void    storeDeviceId(const QString& username, const QString& deviceId);

signals:
    void registerUserSucceeded(QString deviceId);
    void registerUserFailed(QString reason);
    void loginUserSucceeded();
    void loginUserFailed(QString reason);
    void fetchRegistrationNonceSucceeded(QString nonce);
    void fetchRegistrationNonceFailed(QString reason);
    void fetchConversationsSucceeded(QJsonArray conversations);
    void fetchConversationsFailed(QString reason);
    void fetchConversationMessagesSucceeded(QJsonArray messages);
    void fetchConversationMessagesFailed(QString reason);
    void pullMessagesSucceeded(QJsonArray envelopes);
    void pullMessagesFailed();
    void acknowledgeMessageSucceeded(QString messageId);
    void acknowledgeMessageFailed(QString messageId);
    void fetchKeyBundleSucceeded(QJsonObject bundle);
    void fetchKeyBundleFailed(QString reason);
    void createConversationSucceeded(QString conversationId);
    void createConversationFailed(QString reason);

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

    QNetworkRequest makeRequest(
        const QString& path
        );

    QNetworkAccessManager m_network;
    CryptoServiceClient*  m_crypto = nullptr;
    QString               m_authToken;
    QString               m_activeDeviceId;
    QSettings             m_settings;
};
