
#include "ApiClient.h"
#include "CryptoServiceClient.h"

#include "src/network/TLSManager.h"

#include <QDebug>
#include <QNetworkRequest>
#include <QJsonDocument>
#include <QNetworkReply>
#include <QUrl>
#include <QString>
#include <QDateTime>
#include <QMessageAuthenticationCode>
#include <QCryptographicHash>

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

QString ApiClient::storedDeviceId(const QString& username) const
{
    return m_settings.value(QStringLiteral("auth/deviceId/") + username).toString();
}

void ApiClient::storeDeviceId(const QString& username, const QString& deviceId)
{
    m_settings.setValue(QStringLiteral("auth/deviceId/") + username, deviceId);
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

    qDebug() << "[REGISTER REQUEST] POST /auth/register"
             << "| username:" << username;

    auto* reply = m_network.post(request, QJsonDocument(bodyObject).toJson());

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const auto error  = reply->error();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body   = reply->readAll();
        reply->deleteLater();

        qDebug() << "[REGISTER RESPONSE] status:" << status;

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            const QString reason = body.isEmpty()
                ? QStringLiteral("Registration failed.")
                : QString::fromUtf8(body);
            emit registerUserFailed(reason);
            return;
        }

        const auto parsed   = QJsonDocument::fromJson(body).object();
        const auto deviceId = parsed.value(QStringLiteral("deviceId")).toString();
        qDebug() << "[REGISTER RESPONSE] success | deviceId:" << deviceId;
        emit registerUserSucceeded(deviceId);
    });
}

// ── Login — SRP-6a two-round exchange (RFC 5054) ──────────────────────────────

void ApiClient::loginUser(
    const QString& username,
    const QString& password)
{
    qDebug() << "[LOGIN] loginUser called | username:" << username;

    const QString deviceId = storedDeviceId(username);
    if (deviceId.isEmpty()) {
        qDebug() << "[LOGIN] FAILED: no device_id stored";
        emit loginUserFailed(QStringLiteral("No device registered on this device."));
        return;
    }
    m_activeDeviceId = deviceId;

    qDebug() << "[LOGIN] device_id:" << deviceId;
    qDebug() << "[LOGIN] Round 0: calling srpStart (generates A)";

    // Round 0: compute A via Python crypto service (keeps password out of C++)
    const QString A = m_crypto->srpStart(username, password);
    if (A.isEmpty()) {
        qDebug() << "[LOGIN] FAILED: srpStart returned empty A | cryptoError:" << m_crypto->lastError();
        emit loginUserFailed(QStringLiteral("SRP initialisation failed."));
        return;
    }

    qDebug() << "[LOGIN] Round 0 OK: A len:" << A.length() << "| first16:" << A.left(16);

    doSrpInit(username, deviceId, A);
}

void ApiClient::doSrpInit(
    const QString& username,
    const QString& deviceId,
    const QString& A)
{
    qDebug() << "[LOGIN] Round 1: POST /auth/init"
             << "| username:" << username
             << "| device_id:" << deviceId
             << "| A_len:" << A.length();

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

        qDebug() << "[LOGIN] Round 1 response: status:" << status;

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            qDebug() << "[LOGIN] Round 1 FAILED";
            if (status == 429) {
                emit loginUserFailed(QStringLiteral("Too many authentication attempts — please wait and try again."));
            } else {
                emit loginUserFailed(QStringLiteral("Authentication failed."));
            }
            return;
        }

        const auto parsed = QJsonDocument::fromJson(body).object();
        const auto salt   = parsed.value(QStringLiteral("salt")).toString();
        const auto B      = parsed.value(QStringLiteral("serverPublicEphemeral")).toString();

        qDebug() << "[LOGIN] Round 1 OK: salt len:" << salt.length() << "| B len:" << B.length();

        if (salt.isEmpty() || B.isEmpty()) {
            qDebug() << "[LOGIN] Round 1 FAILED: salt or B empty";
            emit loginUserFailed(QStringLiteral("Authentication failed."));
            return;
        }

        qDebug() << "[LOGIN] Round 1: calling srpChallenge (computes M1)";

        // Compute M1 in the Python service — password never leaves the service
        const QString M1 = m_crypto->srpChallenge(salt, B);

        qDebug() << "[LOGIN] srpChallenge result: M1 len:" << M1.length();

        if (M1.isEmpty()) {
            qDebug() << "[LOGIN] Round 1 FAILED: srpChallenge returned empty M1";
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
    qDebug() << "[LOGIN] Round 2: POST /auth/login | username:" << username;

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

        qDebug() << "[LOGIN] Round 2 response: status:" << status;
        qDebug() << "[LOGIN] Round 2 raw body:" << QString::fromUtf8(body.left(500));

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            qDebug() << "[LOGIN] Round 2 FAILED";
            if (status == 429) {
                emit loginUserFailed(QStringLiteral("Too many authentication attempts — please wait and try again."));
            } else {
                emit loginUserFailed(QStringLiteral("Authentication failed."));
            }
            return;
        }

        const auto parsed       = QJsonDocument::fromJson(body).object();
        const auto M2           = parsed.value(QStringLiteral("serverSessionProof")).toString();
        const auto sessionToken = parsed.value(QStringLiteral("session_token")).toString();
        const auto hmacKey      = parsed.value(QStringLiteral("hmac_key")).toString();

        qDebug() << "[LOGIN] Round 2 OK: M2 len:" << M2.length()
                 << "| sessionToken len:" << sessionToken.length();

        if (M2.isEmpty() || sessionToken.isEmpty() || hmacKey.isEmpty()) {
            qDebug() << "[LOGIN] Round 2 FAILED: M2 or session_token or hmac_key empty";
            emit loginUserFailed(QStringLiteral("Authentication failed."));
            return;
        }

        qDebug() << "[LOGIN] Round 2: calling srpVerify (mutual auth check)";

        // Mutual authentication — verify server's proof before trusting session token.
        const QString sessionKey = m_crypto->srpVerify(M2);

        qDebug() << "[LOGIN] srpVerify result: sessionKey len:" << sessionKey.length()
                 << "| cryptoError:" << m_crypto->lastError();

        if (sessionKey.isEmpty()) {
            qDebug() << "[LOGIN] Round 2 FAILED: server proof rejected by client";
            emit loginUserFailed(QStringLiteral("Server authentication failed."));
            return;
        }

        // Use the server-issued HKDF-derived token (not raw K) as the Bearer credential.
        setAuthToken(sessionToken);
        m_hmacKey = hmacKey;

        qDebug() << "[LOGIN] SUCCESS: session established";
        emit loginUserSucceeded();
    });
}

// ── Messaging ─────────────────────────────────────────────────────────────────

void ApiClient::setAuthToken(const QString& token)
{
    m_authToken = token;
}

void ApiClient::clearCredentials()
{
    m_authToken.clear();
    m_hmacKey.clear();
    m_activeDeviceId.clear();
}

void ApiClient::sendMessage(
    const QJsonObject& encryptedEnvelope,
    const QString& localId)
{
    auto request = makeRequest("/messages");
    auto* reply  = m_network.post(request, QJsonDocument(encryptedEnvelope).toJson());
    connect(reply, &QNetworkReply::finished, this, [this, reply, localId]() {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body  = reply->readAll();
        reply->deleteLater();
        if (status < 200 || status >= 300) {
            qWarning() << "[SEND] POST /messages failed | status:" << status
                       << "|" << QString::fromUtf8(body.left(200));
            return;
        }
        qDebug() << "[SEND] POST /messages OK | status:" << status;
        if (!localId.isEmpty()) {
            const QString serverId =
                QJsonDocument::fromJson(body).object().value("id").toString();
            qDebug() << "[SEND] ID mapping: local" << localId << "→ server" << serverId;
            if (!serverId.isEmpty())
                emit messageSentToServer(localId, serverId);
        }
    });
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
        const auto notices   = response.value("notices").toArray();
        emit pullMessagesSucceeded(envelopes);
        if (!notices.isEmpty())
            emit pullNoticesSucceeded(notices);
    });
}

void ApiClient::acknowledgeMessage(
    const QString& messageId,
    const QString& /*deviceId*/)
{
    // Device ID is carried in X-Device-ID header.
    // Percent-encode the server-provided messageId so it can't break out of
    // the path segment (path traversal / URL injection).
    auto request = makeRequest(
        "/messages/" + QString::fromUtf8(QUrl::toPercentEncoding(messageId)) + "/ack");
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

void ApiClient::fetchConversationMessages(const QString& conversationId)
{
    // percent-encode conversation id into path
    auto request = makeRequest(
        "/conversations/" + QString::fromUtf8(QUrl::toPercentEncoding(conversationId)) + "/messages");
    auto* reply = m_network.get(request);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const auto error  = reply->error();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body   = reply->readAll();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            const QString reason = body.isEmpty()
                ? QStringLiteral("Failed to fetch conversation messages.")
                : QString::fromUtf8(body);
            emit fetchConversationMessagesFailed(reason);
            return;
        }

        const auto response = QJsonDocument::fromJson(body).object();
        const auto messages = response.value("messages").toArray();
        emit fetchConversationMessagesSucceeded(messages);
    });
}

void ApiClient::deleteMessage(const QString& messageId)
{
    auto request = makeRequest(
        "/messages/" + QString::fromUtf8(QUrl::toPercentEncoding(messageId)));
    auto* reply  = m_network.deleteResource(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply, messageId]() {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body  = reply->readAll();
        qDebug() << "[DELETE] status:" << status << "|" << QString::fromUtf8(body.left(200));
        reply->deleteLater();
        if (status >= 200 && status < 300)
            emit deleteMessageSucceeded(messageId);
        else
            emit deleteMessageFailed(messageId);
    });
}

void ApiClient::revokeMessage(const QString& messageId, const QString& recipientDeviceId)
{
    auto request = makeRequest(
        "/messages/" + QString::fromUtf8(QUrl::toPercentEncoding(messageId)) + "/revoke");
    QJsonObject body;
    body["recipient_device_id"] = recipientDeviceId;
    auto* reply = m_network.post(request, QJsonDocument(body).toJson());
    connect(reply, &QNetworkReply::finished, this, [this, reply, messageId]() {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body  = reply->readAll();
        qDebug() << "[REVOKE] status:" << status << "|" << QString::fromUtf8(body.left(200));
        reply->deleteLater();
        if (status >= 200 && status < 300)
            emit revokeMessageSucceeded(messageId);
        else
            emit revokeMessageFailed(messageId);
    });
}

void ApiClient::fetchKeyBundle(const QString& username)
{
    // Percent-encode the username before placing it in the path segment.
    auto request = makeRequest(
        "/keys/" + QString::fromUtf8(QUrl::toPercentEncoding(username)));
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

void ApiClient::fetchUserDevices(const QString& username)
{
    auto request = makeRequest(
        "/users/" + QString::fromUtf8(QUrl::toPercentEncoding(username)) + "/devices");
    auto* reply  = m_network.get(request);

    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const auto error  = reply->error();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body   = reply->readAll();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            const QString reason = body.isEmpty()
                ? QStringLiteral("Failed to fetch user devices.")
                : QString::fromUtf8(body);
            emit fetchUserDevicesFailed(reason);
            return;
        }

        const auto devices = QJsonDocument::fromJson(body).object()
                                 .value(QStringLiteral("devices")).toArray();
        emit fetchUserDevicesSucceeded(devices);
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

void ApiClient::fetchMessageBlockchainVerify(const QString& messageId)
{
    auto request = makeRequest(
        "/messages/" + QString::fromUtf8(QUrl::toPercentEncoding(messageId)) + "/blockchain-verify");
    auto* reply  = m_network.get(request);

    connect(reply, &QNetworkReply::finished, this, [this, reply, messageId]() {
        const auto error  = reply->error();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body   = reply->readAll();
        reply->deleteLater();

        if (error != QNetworkReply::NoError || status < 200 || status >= 300) {
            emit blockchainVerifyFailed(messageId, reply->errorString());
            return;
        }

        emit blockchainVerifySucceeded(messageId, QJsonDocument::fromJson(body).object());
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
    if (!m_activeDeviceId.isEmpty()) {
        request.setRawHeader("X-Device-ID", m_activeDeviceId.toUtf8());
    }

    if (!m_authToken.isEmpty()) {
        request.setRawHeader(
            "Authorization",
            ("Bearer " + m_authToken).toUtf8());
    }

    // M4: per-request timestamp + HMAC replay protection.
    // Server requires X-Request-Time (Unix ms) and X-Request-HMAC on every
    // protected route. HMAC = HMAC-SHA256(hmac_key, deviceId + ":" + timestamp).
    if (!m_hmacKey.isEmpty() && !m_activeDeviceId.isEmpty()) {
        const qint64 timestamp = QDateTime::currentMSecsSinceEpoch();
        const QByteArray message =
            (m_activeDeviceId + ":" + QString::number(timestamp)).toUtf8();
        const QByteArray hmac = QMessageAuthenticationCode::hash(
            message,
            QByteArray::fromHex(m_hmacKey.toUtf8()),
            QCryptographicHash::Sha256);
        request.setRawHeader("X-Request-Time", QString::number(timestamp).toUtf8());
        request.setRawHeader("X-Request-HMAC", hmac.toHex());
    }

    return request;
}
