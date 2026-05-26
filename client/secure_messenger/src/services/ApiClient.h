#pragma once

#include <QObject>
#include <QNetworkAccessManager>
#include <QJsonObject>

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

private:
    QNetworkAccessManager m_network;

    QNetworkRequest makeRequest(
        const QString& path
        );
};