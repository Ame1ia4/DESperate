#pragma once

#include <QObject>
#include <QTcpSocket>
#include <QJsonObject>

class CryptoServiceClient : public QObject
{
    Q_OBJECT

public:
    explicit CryptoServiceClient(QObject* parent = nullptr);

    bool unlockKeystore(
        const QString& password
        );

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

    void setRpcTimeoutMs(
        int timeoutMs
        );

signals:
    void encryptCompleted(
        QJsonObject envelope
        );

    void encryptFailed(
        QString reason
        );

    void decryptCompleted(
        QString plaintext
        );

    void decryptFailed(
        QString reason
        );

private:
    QJsonObject rpc(
        const QString& method,
        const QJsonObject& params
        );

    bool ensureConnected();
    bool startLocalCryptoService();
    QString locateServiceScript() const;

    bool writeRequest(
        const QByteArray& payload
        );

    QJsonObject readResponse();

private:
    QTcpSocket m_socket;
    QString m_lastError;
    int m_rpcTimeoutMs = 3000;
    QString m_serviceHost = QStringLiteral("127.0.0.1");
    int m_servicePort = 54231;
    bool m_serviceStarted = false;
};