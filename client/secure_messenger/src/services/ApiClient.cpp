
#include "ApiClient.h"
#include "CryptoServiceClient.h"

#include "src/network/TLSManager.h"

#include <QNetworkRequest>
#include <QJsonDocument>
#include <QNetworkReply>
#include <QUrl>
#include <QString>

ApiClient::ApiClient(CryptoServiceClient* crypto, QObject* parent)
    : QObject(parent)
    , m_crypto(crypto)
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

// ── Device ID persistence ─────────────────────────────────────────────────────

QString ApiClient::storedDeviceId() const
{
    return m_settings.value(QStringLiteral("auth/deviceId")).toString();
}

void ApiClient::storeDeviceId(const QString& deviceId)
{
    m_settings.setValue(QStringLiteral("auth/deviceId"), deviceId);
}

// ── Registration ──────────────────────────────────────────────────────────────

void ApiClient::fetchRegistrationNonce()
{
    auto request = makeRequest("/auth/nonce");
    auto* reply  = m_network.get(request);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const auto error  = reply->error();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body   = reply->readAll();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            emit fetchRegistrationNonceFailed(
                body.isEmpty() ? QStringLiteral("Failed to fetch registration nonce.")
                               : QString::fromUtf8(body));
            return;
        }

        const auto json  = QJsonDocument::fromJson(body).object();
        const auto nonce = json.value(QStringLiteral("nonce")).toString();
        if (nonce.isEmpty()) {
            emit fetchRegistrationNonceFailed(QStringLiteral("Server returned empty nonce."));
            return;
        }

        emit fetchRegistrationNonceSucceeded(nonce);
    });
}

void ApiClient::registerUser(
    const QString& username,
    const QJsonObject& bundle)
{
    auto request = makeRequest("/auth/register");

    QJsonObject bodyObject;
    bodyObject["username"] = username;
    bodyObject["bundle"]   = bundle;

    auto* reply = m_network.post(request, QJsonDocument(bodyObject).toJson());

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const auto error  = reply->error();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body   = reply->readAll();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            const QString reason = body.isEmpty()
                ? QStringLiteral("Registration failed.")
                : QString::fromUtf8(body);
            emit registerUserFailed(reason);
            return;
        }

        const auto parsed   = QJsonDocument::fromJson(body).object();
        const auto deviceId = parsed.value(QStringLiteral("deviceId")).toString();
        emit registerUserSucceeded(deviceId);
    });
}

// ── Login — SRP-6a two-round exchange (RFC 5054) ──────────────────────────────

void ApiClient::loginUser(
    const QString& username,
    const QString& password)
{
    const QString deviceId = storedDeviceId();
    if (deviceId.isEmpty()) {
        emit loginUserFailed(QStringLiteral("No device registered on this device."));
        return;
    }

    // Round 0: compute A via Python crypto service (keeps password out of C++)
    const QString A = m_crypto->srpStart(username, password);
    if (A.isEmpty()) {
        emit loginUserFailed(QStringLiteral("SRP initialisation failed."));
        return;
    }

    doSrpInit(username, deviceId, A);
}

void ApiClient::doSrpInit(
    const QString& username,
    const QString& deviceId,
    const QString& A)
{
    auto request = makeRequest("/auth/init");

    QJsonObject body;
    body["username"]             = username;
    body["device_id"]            = deviceId;
    body["clientPublicEphemeral"] = A;

    auto* reply = m_network.post(request, QJsonDocument(body).toJson());

    connect(reply, &QNetworkReply::finished, this, [this, reply, username, deviceId, A]() {
        const auto error  = reply->error();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body   = reply->readAll();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            emit loginUserFailed(QStringLiteral("Authentication failed."));
            return;
        }

        const auto parsed = QJsonDocument::fromJson(body).object();
        const auto salt   = parsed.value(QStringLiteral("salt")).toString();
        const auto B      = parsed.value(QStringLiteral("serverPublicEphemeral")).toString();

        if (salt.isEmpty() || B.isEmpty()) {
            emit loginUserFailed(QStringLiteral("Authentication failed."));
            return;
        }

        // Compute M1 in the Python service — password never leaves the service
        const QString M1 = m_crypto->srpChallenge(salt, B);
        if (M1.isEmpty()) {
            emit loginUserFailed(QStringLiteral("Authentication failed."));
            return;
        }

        doSrpVerify(username, deviceId, A, M1);
    });
}

void ApiClient::doSrpVerify(
    const QString& username,
    const QString& deviceId,
    const QString& A,
    const QString& M1)
{
    auto request = makeRequest("/auth/login");

    QJsonObject body;
    body["username"]              = username;
    body["device_id"]             = deviceId;
    body["clientPublicEphemeral"] = A;
    body["clientSessionProof"]    = M1;

    auto* reply = m_network.post(request, QJsonDocument(body).toJson());

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const auto error  = reply->error();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body   = reply->readAll();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            emit loginUserFailed(QStringLiteral("Authentication failed."));
            return;
        }

        const auto parsed = QJsonDocument::fromJson(body).object();
        const auto M2     = parsed.value(QStringLiteral("serverSessionProof")).toString();

        if (M2.isEmpty()) {
            emit loginUserFailed(QStringLiteral("Authentication failed."));
            return;
        }

        // Mutual authentication — verify server's proof and get our session token.
        const QString sessionKey = m_crypto->srpVerify(M2);
        if (sessionKey.isEmpty()) {
            emit loginUserFailed(QStringLiteral("Server authentication failed."));
            return;
        }

        // Store session key — sent as Bearer token in all subsequent requests.
        setAuthToken(sessionKey);

        emit loginUserSucceeded();
    });
}

// ── Messaging ─────────────────────────────────────────────────────────────────

void ApiClient::setAuthToken(const QString& token)
{
    m_authToken = token;
}

void ApiClient::sendMessage(
    const QJsonObject& encryptedEnvelope)
{
    auto request = makeRequest("/messages");
    auto* reply  = m_network.post(request, QJsonDocument(encryptedEnvelope).toJson());
    connect(reply, &QNetworkReply::finished, reply, &QNetworkReply::deleteLater);
}

void ApiClient::pullMessages(
    const QString& /*deviceId*/)
{
    // Device ID is carried in X-Device-ID header; not needed in the body.
    auto request = makeRequest("/messages/pending");
    auto* reply  = m_network.get(request);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const auto error  = reply->error();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body   = reply->readAll();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            emit pullMessagesFailed();
            return;
        }

        const auto response  = QJsonDocument::fromJson(body).object();
        const auto envelopes = response.value("envelopes").toArray();
        emit pullMessagesSucceeded(envelopes);
    });
}

void ApiClient::acknowledgeMessage(
    const QString& messageId,
    const QString& /*deviceId*/)
{
    // Device ID is carried in X-Device-ID header.
    auto request = makeRequest("/messages/" + messageId + "/ack");
    auto* reply  = m_network.post(request, QByteArray("{}"));

    connect(reply, &QNetworkReply::finished, this, [this, reply, messageId]() {
        const auto error  = reply->error();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
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
    auto* reply  = m_network.get(request);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const auto error  = reply->error();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body   = reply->readAll();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            const QString reason = body.isEmpty()
                ? QStringLiteral("Failed to load conversations.")
                : QString::fromUtf8(body);
            emit fetchConversationsFailed(reason);
            return;
        }

        const auto response      = QJsonDocument::fromJson(body).object();
        const auto conversations = response.value("conversations").toArray();
        emit fetchConversationsSucceeded(conversations);
    });
}

void ApiClient::fetchKeyBundle(const QString& username)
{
    auto request = makeRequest("/keys/" + username);
    auto* reply  = m_network.get(request);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const auto error  = reply->error();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body   = reply->readAll();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            const QString reason = body.isEmpty()
                ? QStringLiteral("Failed to fetch key bundle.")
                : QString::fromUtf8(body);
            emit fetchKeyBundleFailed(reason);
            return;
        }

        const auto bundle = QJsonDocument::fromJson(body).object();
        emit fetchKeyBundleSucceeded(bundle);
    });
}

void ApiClient::createConversation(const QString& otherUsername)
{
    auto request = makeRequest("/conversations");

    QJsonObject body;
    body["other_username"] = otherUsername;

    auto* reply = m_network.post(request, QJsonDocument(body).toJson());

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const auto error  = reply->error();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body   = reply->readAll();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            const QString reason = body.isEmpty()
                ? QStringLiteral("Failed to create conversation.")
                : QString::fromUtf8(body);
            emit createConversationFailed(reason);
            return;
        }

        const auto parsed = QJsonDocument::fromJson(body).object();
        const auto convId = parsed.value(QStringLiteral("conversationId")).toString();
        emit createConversationSucceeded(convId);
    });
}

// ── Private ───────────────────────────────────────────────────────────────────

QNetworkRequest ApiClient::makeRequest(
    const QString& path)
{
    QString apiHost = qEnvironmentVariable("DESPERATE_API_HOST");
    if (apiHost.trimmed().isEmpty()) {
        apiHost = QStringLiteral("https://des-perate.theburkenator.com");
    } else if (!apiHost.contains(QStringLiteral("://"))) {
        apiHost.prepend(QStringLiteral("https://"));
    }

    QNetworkRequest request(QUrl(apiHost + path));

    request.setHeader(
        QNetworkRequest::ContentTypeHeader,
        "application/json");

    // Always enforce TLS 1.3 with peer certificate verification.
    request.setSslConfiguration(TLSManager::defaultConfig());

    // Session authentication headers — set on every request so protected
    // routes can verify the device identity and session token.
    const QString deviceId = storedDeviceId();
    if (!deviceId.isEmpty()) {
        request.setRawHeader("X-Device-ID", deviceId.toUtf8());
    }

    if (!m_authToken.isEmpty()) {
        request.setRawHeader(
            "Authorization",
            ("Bearer " + m_authToken).toUtf8());
    }

    return request;
}
