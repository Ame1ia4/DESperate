#include "ApiClient.h"

#include <QNetworkRequest>
#include <QJsonDocument>
#include <QSslConfiguration>
#include <QNetworkReply>
#include <QUrl>
#include <QString>
#include <QProcessEnvironment>

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
        const auto payload = reply->readAll();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            const QString reason = payload.isEmpty()
                ? QStringLiteral("Registration failed.")
                : QString::fromUtf8(payload);
            emit registerUserFailed(reason);
            return;
        }

        emit registerUserSucceeded();
    });
}

void ApiClient::loginUser(
    const QString& username,
    const QString& password
    )
{
    auto request = makeRequest("/auth/login");

    QJsonObject bodyObject;
    bodyObject["username"] = username;
    bodyObject["password"] = password;

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
            QString reason = QStringLiteral("No matching credentials found.");
            if (!payload.isEmpty()) {
                const auto parsed = QJsonDocument::fromJson(payload).object();
                if (!parsed.value("error").toString().trimmed().isEmpty()) {
                    reason = parsed.value("error").toString();
                }
            }
            emit loginUserFailed(reason);
            return;
        }

        emit loginUserSucceeded();
    });
}

QNetworkRequest ApiClient::makeRequest(
    const QString& path
    )
{
    QString apiHost = qEnvironmentVariable("DESPERATE_API_HOST");
    if (apiHost.trimmed().isEmpty()) {
        apiHost = QStringLiteral("http://127.0.0.1");
    } else if (!apiHost.contains(QStringLiteral("://"))) {
        apiHost.prepend(QStringLiteral("http://"));
    }

    QNetworkRequest request(
        QUrl(apiHost + path)
        );

    request.setHeader(
        QNetworkRequest::ContentTypeHeader,
        "application/json"
        );

    if (request.url().scheme() == QLatin1String("https")) {
        QSslConfiguration ssl;
        ssl.setProtocol(QSsl::TlsV1_3);
        request.setSslConfiguration(ssl);
    }

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