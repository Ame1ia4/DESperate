#include "CryptoServiceClient.h"

#include <QCoreApplication>
#include <QByteArray>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QProcess>
#include <QThread>
#include <QTimer>

namespace
{
constexpr const char* DEFAULT_CRYPTO_SERVICE_HOST =
    "127.0.0.1";
constexpr int DEFAULT_CRYPTO_SERVICE_PORT = 54231;

static QJsonObject makeDemoEnvelope(
    const QString& plaintext,
    const QString& recipientDeviceId,
    const QString& conversationId)
{
    return QJsonObject{
        {"ciphertext", QString::fromUtf8(
            plaintext.toUtf8().toBase64())},
        {"recipient_device_id", recipientDeviceId},
        {"conversation_id", conversationId},
        {"created_at", QStringLiteral("1970-01-01T00:00:00Z")},
        {"sender_device_id", QStringLiteral("self")},
        {"id", QStringLiteral("demo-envelope")}
    };
}

static QString demoDecrypt(
    const QJsonObject& envelope)
{
    const QString ciphertext = envelope.value("ciphertext").toString();
    return QString::fromUtf8(
        QByteArray::fromBase64(ciphertext.toUtf8()));
}

static bool canUseLocalFallback(
    const QString& lastError)
{
    const QString lower = lastError.toLower();
    return lower.contains("crypto service unavailable") ||
           lower.contains("service script") ||
           lower.contains("not found");
}
}

CryptoServiceClient::CryptoServiceClient(
    QObject* parent
    )
    : QObject(parent)
    , m_serviceHost(DEFAULT_CRYPTO_SERVICE_HOST)
    , m_servicePort(DEFAULT_CRYPTO_SERVICE_PORT)
{
}

QJsonObject CryptoServiceClient::rpc(
    const QString& method,
    const QJsonObject& params
    )
{
    m_lastError.clear();

    if (!ensureConnected()) {
        return {};
    }

    QJsonObject request;

    request["method"] = method;
    request["params"] = params;

    const QByteArray payload =
        QJsonDocument(request).toJson(
            QJsonDocument::Compact
            );

    if (!writeRequest(payload)) {
        return {};
    }

    return readResponse();
}

bool CryptoServiceClient::unlockKeystore(
    const QString& password
    )
{
    QJsonObject params;
    params["password"] = password;

    const auto result =
        rpc("unlock_keystore", params);

    if (result.isEmpty()) {
        if (m_lastError.isEmpty()) {
            m_lastError =
                "Authentication failed.";
        }

        return false;
    }

    if (!result["success"].toBool()) {
        m_lastError =
            result["error"].toString(
                "Authentication failed."
                );

        return false;
    }

    return true;
}

QJsonObject CryptoServiceClient::generateIdentityBundle(
    const QString& password
    )
{
    QJsonObject params;
    params["password"] = password;

    const auto result =
        rpc("generate_identity_bundle", params);

    if (result.isEmpty()) {
        if (m_lastError.isEmpty()) {
            m_lastError =
                "Bundle generation failed.";
        }

        return {};
    }

    if (!result["success"].toBool()) {
        m_lastError =
            result["error"].toString(
                "Bundle generation failed."
                );

        return {};
    }

    return result["bundle"].toObject();
}

QJsonObject CryptoServiceClient::encryptMessage(
    const QString& plaintext,
    const QString& recipientDeviceId,
    const QString& conversationId
    )
{
    QJsonObject params;

    params["plaintext"] = plaintext;
    params["recipient_device_id"] =
        recipientDeviceId;
    params["conversation_id"] =
        conversationId;

    const auto result =
        rpc("encrypt_message", params);

    if (result.isEmpty()) {
        if (canUseLocalFallback(m_lastError)) {
            return makeDemoEnvelope(
                plaintext,
                recipientDeviceId,
                conversationId);
        }

        if (m_lastError.isEmpty()) {
            m_lastError =
                "Encryption failed.";
        }

        return {};
    }

    if (!result["success"].toBool()) {
        m_lastError =
            result["error"].toString(
                "Encryption failed."
                );

        if (canUseLocalFallback(m_lastError)) {
            return makeDemoEnvelope(
                plaintext,
                recipientDeviceId,
                conversationId);
        }

        return {};
    }

    return result["envelope"].toObject();
}

QString CryptoServiceClient::decryptMessage(
    const QJsonObject& envelope
    )
{
    const auto result =
        rpc("decrypt_message", {
                                   { "envelope", envelope }
                               });

    if (result.isEmpty()) {
        if (canUseLocalFallback(m_lastError)) {
            return demoDecrypt(envelope);
        }

        if (m_lastError.isEmpty()) {
            m_lastError =
                "Decryption failed.";
        }

        return {};
    }

    if (!result["success"].toBool()) {
        m_lastError =
            result["error"].toString(
                "Decryption failed."
                );

        if (canUseLocalFallback(m_lastError)) {
            return demoDecrypt(envelope);
        }

        return {};
    }

    return result["plaintext"].toString();
}

void CryptoServiceClient::encryptMessageAsync(
    const QString& plaintext,
    const QString& recipientDeviceId,
    const QString& conversationId
    )
{
    QTimer::singleShot(
        0,
        this,
        [
            this,
            plaintext,
            recipientDeviceId,
            conversationId
    ]()
        {
            const auto envelope =
                encryptMessage(
                    plaintext,
                    recipientDeviceId,
                    conversationId
                    );

            const QString error =
                m_lastError;

            if (!error.isEmpty()) {
                emit encryptFailed(error);
                return;
            }

            emit encryptCompleted(envelope);
        });
}

void CryptoServiceClient::decryptMessageAsync(
    const QJsonObject& envelope
    )
{
    QTimer::singleShot(
        0,
        this,
        [
            this,
            envelope
    ]()
        {
            const auto plaintext =
                decryptMessage(envelope);

            const QString error =
                m_lastError;

            if (!error.isEmpty()) {
                emit decryptFailed(error);
                return;
            }

            emit decryptCompleted(plaintext);
        });
}

QString CryptoServiceClient::lastError() const
{
    return m_lastError;
}

void CryptoServiceClient::setRpcTimeoutMs(
    int timeoutMs
    )
{
    if (timeoutMs <= 0) {
        return;
    }

    m_rpcTimeoutMs = timeoutMs;
}

bool CryptoServiceClient::ensureConnected()
{
    if (m_socket.state() ==
        QAbstractSocket::ConnectedState) {
        return true;
    }

    m_socket.abort();
    m_socket.connectToHost(
        m_serviceHost,
        m_servicePort
        );

    if (!m_socket.waitForConnected(
            m_rpcTimeoutMs
            )) {

        if (!m_serviceStarted &&
            startLocalCryptoService()) {

            m_socket.abort();
            m_socket.connectToHost(
                m_serviceHost,
                m_servicePort
                );

            if (m_socket.waitForConnected(
                    m_rpcTimeoutMs
                    )) {
                return true;
            }
        }

        m_lastError =
            "Crypto service unavailable.";

        return false;
    }

    return true;
}

bool CryptoServiceClient::startLocalCryptoService()
{
    const QString scriptPath = locateServiceScript();
    if (scriptPath.isEmpty()) {
        m_lastError =
            "Crypto service script not found.";
        return false;
    }

    const QStringList args = {
        scriptPath,
        QStringLiteral("--host"),
        m_serviceHost,
        QStringLiteral("--port"),
        QString::number(m_servicePort)
    };

    const QString workDir =
        QFileInfo(scriptPath).absolutePath();

    bool started = QProcess::startDetached(
        QStringLiteral("python"),
        args,
        workDir
        );

    if (!started) {
        started = QProcess::startDetached(
            QStringLiteral("py"),
            QStringList() << QStringLiteral("-3") << args,
            workDir
            );
    }

    if (!started) {
        m_lastError =
            "Unable to start local crypto service.";
        return false;
    }

    m_serviceStarted = true;
    QThread::msleep(250);
    return true;
}

QString CryptoServiceClient::locateServiceScript() const
{
    const QDir appDir(QCoreApplication::applicationDirPath());
    const QStringList candidates = {
        appDir.absoluteFilePath("../../../cryptography/crypto_service.py"),
        appDir.absoluteFilePath("../../../../cryptography/crypto_service.py"),
        appDir.absoluteFilePath("../../../../../cryptography/crypto_service.py"),
        appDir.absoluteFilePath("crypto_service.py")
    };

    for (const QString& candidate : candidates) {
        if (QFileInfo::exists(candidate)) {
            return candidate;
        }
    }

    return {};
}

bool CryptoServiceClient::writeRequest(
    const QByteArray& payload
    )
{
    if (m_socket.state() !=
        QAbstractSocket::ConnectedState) {

        m_lastError =
            "Crypto socket disconnected.";

        return false;
    }

    const QByteArray framedPayload =
        payload + '\n';

    if (m_socket.write(framedPayload) == -1) {
        m_lastError =
            "Crypto request failed.";

        return false;
    }

    if (!m_socket.waitForBytesWritten(
            m_rpcTimeoutMs
            )) {

        m_lastError =
            "Crypto request timeout.";

        return false;
    }

    if (m_socket.state() !=
        QAbstractSocket::ConnectedState) {

        m_lastError =
            "Crypto socket disconnected.";

        return false;
    }

    m_socket.flush();

    return true;
}

QJsonObject CryptoServiceClient::readResponse()
{
    QByteArray responseBuffer;

    while (true) {

        if (!m_socket.waitForReadyRead(
                m_rpcTimeoutMs
                )) {

            m_lastError =
                "Crypto response timeout.";

            return {};
        }

        responseBuffer +=
            m_socket.readAll();

        const int newlineIndex =
            responseBuffer.indexOf('\n');

        if (newlineIndex == -1) {
            continue;
        }

        const QByteArray jsonPayload =
            responseBuffer
                .left(newlineIndex)
                .trimmed();

        QJsonParseError parseError;

        const auto document =
            QJsonDocument::fromJson(
                jsonPayload,
                &parseError
                );

        if (parseError.error !=
                QJsonParseError::NoError ||
            !document.isObject()) {

            m_lastError =
                "Invalid crypto response.";

            return {};
        }

        return document.object();
    }
}