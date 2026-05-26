#include "CryptoBridge.h"

#include <QJsonDocument>

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
    QJsonObject request;

    request["method"] = method;
    request["params"] = params;

    QByteArray payload =
        QJsonDocument(request).toJson();

    m_socket.write(payload);
    m_socket.flush();
    m_socket.waitForReadyRead();

    QByteArray response = m_socket.readAll();

    return QJsonDocument::fromJson(response).object();
}

bool CryptoServiceClient::unlockKeystore(
    const QString& password
    )
{
    QJsonObject params;
    params["password"] = password;

    auto result = rpc("unlock_keystore", params);

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

    return rpc("encrypt_message", params);
}