#include "ApiClient.h"

#include <QNetworkRequest>
#include <QJsonDocument>
#include <QSslConfiguration>
#include <QNetworkReply>

ApiClient::ApiClient(QObject* parent)
    : QObject(parent)
{
}

void ApiClient::registerUser(
    const QString& username,
    const QJsonObject& bundle
    )
{
    auto request = makeRequest("/auth/register");

    QJsonObject bodyObject;
    bodyObject["username"] = username;
    bodyObject["bundle"] = bundle;

    QByteArray body = QJsonDocument(bodyObject).toJson();
    auto* reply = m_network.post(request, body);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const auto error = reply->error();
        const auto status = reply->attribute(
            QNetworkRequest::HttpStatusCodeAttribute
            ).toInt();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            emit registerUserFailed();
            return;
        }

        emit registerUserSucceeded();
    });
}

QNetworkRequest ApiClient::makeRequest(
    const QString& path
    )
{
    QNetworkRequest request(
        QUrl("https://api.example.com" + path)
        );

    request.setHeader(
        QNetworkRequest::ContentTypeHeader,
        "application/json"
        );

    QSslConfiguration ssl;
    ssl.setProtocol(QSsl::TlsV1_3);

    request.setSslConfiguration(ssl);

    return request;
}

void ApiClient::sendMessage(
    const QJsonObject& encryptedEnvelope
    )
{
    auto request = makeRequest("/messages/send");

    QByteArray body =
        QJsonDocument(encryptedEnvelope).toJson();

    auto* reply = m_network.post(request, body);
    connect(reply, &QNetworkReply::finished, reply, &QNetworkReply::deleteLater);
}

void ApiClient::pullMessages(
    const QString& deviceId
    )
{
    auto request = makeRequest("/messages/pull");

    QJsonObject bodyObject;
    bodyObject["device_id"] = deviceId;

    QByteArray body = QJsonDocument(bodyObject).toJson();
    auto* reply = m_network.post(request, body);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const auto error = reply->error();
        const auto status = reply->attribute(
            QNetworkRequest::HttpStatusCodeAttribute
            ).toInt();
        const auto payload = reply->readAll();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            emit pullMessagesFailed();
            return;
        }

        const auto response = QJsonDocument::fromJson(payload).object();
        const auto envelopes = response.value("envelopes").toArray();
        emit pullMessagesSucceeded(envelopes);
    });
}

void ApiClient::acknowledgeMessage(
    const QString& messageId,
    const QString& deviceId
    )
{
    auto request = makeRequest("/messages/ack");

    QJsonObject bodyObject;
    bodyObject["message_id"] = messageId;
    bodyObject["device_id"] = deviceId;

    QByteArray body = QJsonDocument(bodyObject).toJson();
    auto* reply = m_network.post(request, body);
    connect(reply, &QNetworkReply::finished, this, [this, reply, messageId]() {
        const auto error = reply->error();
        const auto status = reply->attribute(
            QNetworkRequest::HttpStatusCodeAttribute
            ).toInt();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            emit acknowledgeMessageFailed(messageId);
            return;
        }

        emit acknowledgeMessageSucceeded(messageId);
    });
}