#pragma once

#include <QObject>
#include <QLocalSocket>
#include <QJsonObject>

class CryptoServiceClient : public QObject
{
    Q_OBJECT

public:
    explicit CryptoServiceClient(QObject* parent = nullptr);

    bool unlockKeystore(const QString& password);

    QJsonObject generateIdentityBundle(
        const QString& password
        );

    QJsonObject encryptMessage(
        const QString& plaintext,
        const QString& recipientDeviceId,
        const QString& conversationId
        );

    QString decryptMessage(
        const QJsonObject& envelope
        );

private:
    QJsonObject rpc(
        const QString& method,
        const QJsonObject& params
        );

    QLocalSocket m_socket;
};