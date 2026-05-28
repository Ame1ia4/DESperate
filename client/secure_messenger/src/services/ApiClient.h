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
    void registerUserFailed();
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