#include "ApiClient.h"

#include <QNetworkRequest>
#include <QJsonDocument>
#include <QSslConfiguration>

ApiClient::ApiClient(QObject* parent)
    : QObject(parent)
{
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

    m_network.post(request, body);
}