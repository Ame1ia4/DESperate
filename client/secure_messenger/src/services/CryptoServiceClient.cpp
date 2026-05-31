
#include "CryptoServiceClient.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QEventLoop>
#include <QFileInfo>
#include <QJsonDocument>
#include <QProcess>
#include <QUuid>

    CryptoServiceClient::CryptoServiceClient(
        QObject* parent)
    : QObject(parent)
{
}

bool CryptoServiceClient::unlockKeystore(
    const QString& password)
{
    if (password.isEmpty()) {

        m_lastError =
            "Password required.";

        return false;
    }

    const QJsonObject response =
        rpc(
            "unlock_keystore",
            {
                {"password", password}
            });

    const bool success =
        response.value("success")
            .toBool(false);

    if (!success) {

        m_lastError =
            response.value("error")
                .toString(
                    "Keystore unlock failed.");

        return false;
    }

    m_lastError.clear();

    return true;
}

QJsonObject
CryptoServiceClient::generateIdentityBundle(
    const QString& password)
{
    return rpc(
        "generate_identity_bundle",
        {
            {"password", password}
        });
}

QJsonObject
CryptoServiceClient::encryptMessage(
    const QString& plaintext,
    const QString& recipientDeviceId,
    const QString& conversationId)
{
    return rpc(
        "encrypt_message",
        {
            {"plaintext", plaintext},
            {"recipient_device_id",
             recipientDeviceId},
            {"conversation_id",
             conversationId}
        });
}

QString CryptoServiceClient::decryptMessage(
    const QJsonObject& envelope)
{
    const QJsonObject response =
        rpc(
            "decrypt_message",
            {
                {"envelope", envelope}
            });

    return response.value("plaintext")
        .toString();
}

void CryptoServiceClient::encryptMessageAsync(
    const QString& requestId,
    const QByteArray& plaintext,
    const QString& recipientDeviceId,
    const QString& conversationId)
{
    QMetaObject::invokeMethod(
        this,
        [=]() {

            const QJsonObject response =
                encryptMessage(
                    QString::fromUtf8(
                        plaintext),
                    recipientDeviceId,
                    conversationId);

            if (response.isEmpty()) {

                emit encryptFailed(
                    requestId,
                    m_lastError.isEmpty()
                        ? "Encryption failed."
                        : m_lastError);

                return;
            }

            emit encryptCompleted(
                requestId,
                response);
        },
        Qt::QueuedConnection);
}

void CryptoServiceClient::decryptMessageAsync(
    const QString& requestId,
    const QJsonObject& envelope)
{
    QMetaObject::invokeMethod(
        this,
        [=]() {

            const QString plaintext =
                decryptMessage(
                    envelope);

            if (plaintext.isEmpty()) {

                emit decryptFailed(
                    requestId,
                    m_lastError.isEmpty()
                        ? "Decryption failed."
                        : m_lastError);

                return;
            }

            emit decryptCompleted(
                requestId,
                plaintext);
        },
        Qt::QueuedConnection);
}

QString CryptoServiceClient::lastError() const
{
    return m_lastError;
}

void CryptoServiceClient::setRpcTimeoutMs(
    int timeoutMs)
{
    if (timeoutMs <= 0) {
        return;
    }

    m_rpcTimeoutMs = timeoutMs;
}

QJsonObject CryptoServiceClient::rpc(
    const QString& method,
    const QJsonObject& params)
{
    if (!ensureConnected()) {
        return {};
    }

    QJsonObject request;

    request["id"] =
        QUuid::createUuid().toString();

    request["method"] =
        method;

    request["params"] =
        params;

    const QByteArray payload =
        QJsonDocument(request)
            .toJson(
                QJsonDocument::Compact);

    if (!writeRequest(payload)) {
        return {};
    }

    return readResponse();
}

bool CryptoServiceClient::ensureConnected()
{
    if (m_socket.state() ==
        QAbstractSocket::ConnectedState) {

        return true;
    }

    m_socket.connectToHost(
        m_serviceHost,
        m_servicePort);

    if (m_socket.waitForConnected(
            m_rpcTimeoutMs)) {

        return true;
    }

    if (!m_serviceStarted) {

        if (!startLocalCryptoService()) {

            m_lastError =
                "Unable to start crypto service.";

            return false;
        }

        m_serviceStarted = true;

        m_socket.connectToHost(
            m_serviceHost,
            m_servicePort);

        if (m_socket.waitForConnected(
                m_rpcTimeoutMs)) {

            return true;
        }
    }

    m_lastError =
        m_socket.errorString();

    return false;
}

bool CryptoServiceClient::startLocalCryptoService()
{
    const QString script =
        locateServiceScript();

    if (script.isEmpty()) {

        m_lastError =
            "Crypto service script missing.";

        return false;
    }

    return QProcess::startDetached(
        script);
}

QString CryptoServiceClient::locateServiceScript()
    const
{
    const QString basePath =
        QCoreApplication
        ::applicationDirPath();

#ifdef Q_OS_WIN
    const QString exe = QStringLiteral(".exe");
#else
    const QString exe = QStringLiteral("");
#endif

    const QString bundled =
        basePath + "/crypto_service/crypto_service" + exe;

    if (QFileInfo::exists(bundled)) {
        return bundled;
    }

    return {};
}

bool CryptoServiceClient::writeRequest(
    const QByteArray& payload)
{
    const QByteArray framed =
        payload + '\n';

    if (m_socket.write(framed) == -1) {

        m_lastError =
            m_socket.errorString();

        return false;
    }

    if (!m_socket.waitForBytesWritten(
            m_rpcTimeoutMs)) {

        m_lastError =
            "Timed out writing request.";

        return false;
    }

    return true;
}

QJsonObject
CryptoServiceClient::readResponse()
{
    if (!m_socket.waitForReadyRead(
            m_rpcTimeoutMs)) {

        m_lastError =
            "Timed out waiting for response.";

        return {};
    }

    const QByteArray responseBytes =
        m_socket.readLine();

    const auto document =
        QJsonDocument::fromJson(
            responseBytes);

    if (!document.isObject()) {

        m_lastError =
            "Invalid RPC response.";

        return {};
    }

    const QJsonObject response =
        document.object();

    if (response.contains("error")) {

        m_lastError =
            response.value("error")
                .toString();

        return {};
    }

    return response;
}
