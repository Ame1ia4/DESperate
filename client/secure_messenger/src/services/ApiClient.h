#pragma once

#include <QObject>
#include <QNetworkAccessManager>
#include <QJsonObject>
#include <QJsonArray>

class ApiClient : public QObject
{
    Q_OBJECT

public:
    explicit ApiClient(QObject* parent = nullptr);

    void registerUser(
        const QString& username,
        const QJsonObject& bundle
        );
    void loginUser(
        const QString& username,
        const QString& password
        );

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

signals:
    void registerUserSucceeded();
    void registerUserFailed(QString reason);
    void loginUserSucceeded();
    void loginUserFailed(QString reason);
    void pullMessagesSucceeded(QJsonArray envelopes);
    void pullMessagesFailed();
    void acknowledgeMessageSucceeded(QString messageId);
    void acknowledgeMessageFailed(QString messageId);

private:
    QNetworkAccessManager m_network;

    QNetworkRequest makeRequest(
        const QString& path
        );
};