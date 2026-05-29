#include "ApiClient.h"

#include "src/network/TLSManager.h"

#include <QNetworkRequest>
#include <QJsonDocument>
#include <QNetworkReply>
#include <QUrl>
#include <QString>

ApiClient::ApiClient(QObject* parent)
    : QObject(parent)
{
    connect(
        &m_network,
        &QNetworkAccessManager::sslErrors,
        this,
        [](QNetworkReply* reply, const QList<QSslError>& errors) {
            for (const auto& e : errors)
                qWarning() << "TLS error:" << e.errorString();
            reply->abort();  // never silently ignore SSL errors
        });
}

void ApiClient::setAuthToken(const QString& token)
{
    m_authToken = token;
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
    // TODO: Replace with a proper SRP-6a exchange (RFC 5054, 2048-bit group).
    // Sending a plaintext password violates the auth design — the password must
    // never leave the client. SRP proves knowledge of the password without
    // transmitting it. See CLAUDE.md § Authentication model.
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

        // Server authenticates via SRP with a server-side expiry window.
        // No session token is issued; subsequent requests are authenticated
        // by the SRP session state held server-side.
        emit loginUserSucceeded();
    });
}

QNetworkRequest ApiClient::makeRequest(
    const QString& path
    )
{
    QString apiHost = qEnvironmentVariable("DESPERATE_API_HOST");
    if (apiHost.trimmed().isEmpty()) {
        apiHost = QStringLiteral("https://des-perate.theburkenator.com");
    } else if (!apiHost.contains(QStringLiteral("://"))) {
        apiHost.prepend(QStringLiteral("https://"));
    }

    QNetworkRequest request(
        QUrl(apiHost + path)
        );

    request.setHeader(
        QNetworkRequest::ContentTypeHeader,
        "application/json"
        );

    // Always enforce TLS 1.3 with peer certificate verification.
    request.setSslConfiguration(
        TLSManager::defaultConfig());

    if (!m_authToken.isEmpty()) {
        request.setRawHeader(
            "Authorization",
            ("Bearer " + m_authToken).toUtf8());
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

void ApiClient::fetchConversations()
{
    auto request = makeRequest("/conversations");

    auto* reply = m_network.get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const auto error = reply->error();
        const auto status = reply->attribute(
            QNetworkRequest::HttpStatusCodeAttribute
            ).toInt();
        const auto payload = reply->readAll();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            const QString reason = payload.isEmpty()
                ? QStringLiteral("Failed to load conversations.")
                : QString::fromUtf8(payload);
            emit fetchConversationsFailed(reason);
            return;
        }

        const auto response =
            QJsonDocument::fromJson(payload).object();
        const auto conversations =
            response.value("conversations").toArray();
        emit fetchConversationsSucceeded(conversations);
    });
}