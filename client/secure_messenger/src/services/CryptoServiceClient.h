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

    void encryptMessageAsync(
        const QString& plaintext,
        const QString& recipientDeviceId,
        const QString& conversationId
        );

    void decryptMessageAsync(
        const QJsonObject& envelope
        );

    QString lastError() const;
    void setRpcTimeoutMs(int timeoutMs);

signals:
    void encryptCompleted(QJsonObject envelope);
    void encryptFailed(QString reason);
    void decryptCompleted(QString plaintext);
    void decryptFailed(QString reason);

private:
    QJsonObject rpc(
        const QString& method,
        const QJsonObject& params
        );

    bool ensureConnected();
    bool writeRequest(const QByteArray& payload);
    QJsonObject readResponse();

    QLocalSocket m_socket;
    QString m_lastError;
    int m_rpcTimeoutMs = 3000;
};