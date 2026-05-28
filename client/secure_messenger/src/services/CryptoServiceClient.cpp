#include "CryptoServiceClient.h"

#include <QJsonDocument>
#include <QTimer>

CryptoServiceClient::CryptoServiceClient(QObject* parent)
    : QObject(parent)
{
    m_socket.connectToServer("pqmessenger_crypto");
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

    QByteArray payload =
        QJsonDocument(request).toJson();

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

    auto result = rpc("unlock_keystore", params);

    if (result.isEmpty()) {
        if (m_lastError.isEmpty()) {
            m_lastError = "Authentication failed.";
        }
        return false;
    }

    if (!result["success"].toBool()) {
        m_lastError = "Authentication failed.";
        return false;
    }

    return result["success"].toBool();
}

QJsonObject CryptoServiceClient::encryptMessage(
    const QString& plaintext,
    const QString& recipientDeviceId,
    const QString& conversationId
    )
{
    QJsonObject params;

    params["plaintext"] = plaintext;
    params["recipient_device_id"] = recipientDeviceId;
    params["conversation_id"] = conversationId;

    auto result = rpc("encrypt_message", params);
    if (result.isEmpty() || !result["success"].toBool()) {
        m_lastError = "Encryption failed.";
        return {};
    }

    return result["envelope"].toObject();
}

QJsonObject CryptoServiceClient::generateIdentityBundle(
    const QString& password
    )
{
    QJsonObject params;
    params["password"] = password;

    auto result = rpc("generate_identity_bundle", params);
    if (result.isEmpty() || !result["success"].toBool()) {
        m_lastError = "Bundle generation failed.";
        return {};
    }

    return result["bundle"].toObject();
}

QString CryptoServiceClient::decryptMessage(
    const QJsonObject& envelope
    )
{
    auto result = rpc("decrypt_message", {
        {"envelope", envelope}
    });

    if (result.isEmpty() || !result["success"].toBool()) {
        m_lastError = "Decryption failed.";
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
    QTimer::singleShot(0, this, [this,
                                 plaintext,
                                 recipientDeviceId,
                                 conversationId]() {
        const auto envelope = encryptMessage(
            plaintext,
            recipientDeviceId,
            conversationId
            );

        if (!m_lastError.isEmpty()) {
            emit encryptFailed(m_lastError);
            return;
        }

        emit encryptCompleted(envelope);
    });
}

void CryptoServiceClient::decryptMessageAsync(
    const QJsonObject& envelope
    )
{
    QTimer::singleShot(0, this, [this, envelope]() {
        const auto plaintext = decryptMessage(envelope);
        if (!m_lastError.isEmpty()) {
            emit decryptFailed(m_lastError);
            return;
        }

        emit decryptCompleted(plaintext);
    });
}

QString CryptoServiceClient::lastError() const
{
    return m_lastError;
}

void CryptoServiceClient::setRpcTimeoutMs(int timeoutMs)
{
    if (timeoutMs <= 0) {
        return;
    }

    m_rpcTimeoutMs = timeoutMs;
}

bool CryptoServiceClient::ensureConnected()
{
    if (m_socket.state() == QLocalSocket::ConnectedState) {
        return true;
    }

    m_socket.abort();
    m_socket.connectToServer("pqmessenger_crypto");

    if (!m_socket.waitForConnected(m_rpcTimeoutMs)) {
        m_lastError = "Crypto service unavailable.";
        return false;
    }

    return true;
}

bool CryptoServiceClient::writeRequest(
    const QByteArray& payload
    )
{
    if (m_socket.write(payload) == -1) {
        m_lastError = "Crypto request failed.";
        return false;
    }

    if (!m_socket.waitForBytesWritten(m_rpcTimeoutMs)) {
        m_lastError = "Crypto request timeout.";
        return false;
    }

    m_socket.flush();
    return true;
}

QJsonObject CryptoServiceClient::readResponse()
{
    if (!m_socket.waitForReadyRead(m_rpcTimeoutMs)) {
        m_lastError = "Crypto response timeout.";
        return {};
    }

    const QByteArray response = m_socket.readAll();
    QJsonParseError parseError;
    auto doc = QJsonDocument::fromJson(response, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        m_lastError = "Invalid crypto response.";
        return {};
    }

    return doc.object();
}