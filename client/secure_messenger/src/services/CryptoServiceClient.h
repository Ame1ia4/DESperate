
#pragma once

#include <QObject>
#include <QProcess>
#include <QTcpSocket>
#include <QHash>
#include <QJsonObject>

    class CryptoServiceClient : public QObject
{
    Q_OBJECT

public:
    explicit CryptoServiceClient(
        QObject* parent = nullptr);

    ~CryptoServiceClient();

    bool unlockKeystore(
        const QString& password);

    QJsonObject generateIdentityBundle(
        const QString& username,
        const QString& password,
        const QString& nonce);

    // SRP-6a client session (RFC 5054, 3072-bit group, SHA-256).
    // Call srpStart → srpChallenge → srpVerify in order.
    QString srpStart(
        const QString& username,
        const QString& password);

    QString srpChallenge(
        const QString& saltHex,
        const QString& bHex);

    // Returns the session key hex on success (to be used as Bearer token),
    // or an empty string on failure.
    QString srpVerify(
        const QString& m2Hex);

    // Establish a PQXDH session as the initiator.
    // remoteBundleJson: JSON string returned by GET /keys/:username.
    // Returns true if the session was established successfully.
    bool initiateSession(
        const QString& conversationId,
        const QByteArray& remoteBundleJson);

    // Synchronous encrypt/decrypt APIs
    QJsonObject encryptMessage(
        const QString& plaintext,
        const QString& recipientDeviceId,
        const QString& conversationId);

    QString decryptMessage(
        const QJsonObject& envelope);

    // Async APIs with request correlation
    void encryptMessageAsync(
        const QString& requestId,
        const QByteArray& plaintext,
        const QString& recipientDeviceId,
        const QString& conversationId);

    void decryptMessageAsync(
        const QString& requestId,
        const QJsonObject& envelope);

    bool hasSession(const QString& conversationId);

    bool resetSession(const QString& conversationId);

    // Returns { new_salt, new_verifier } on success, or { error } on failure.
    QJsonObject preparePasswordChange(
        const QString& username,
        const QString& currentPassword,
        const QString& newPassword);

    bool commitPasswordChange();

    QString lastError() const;

    void setRpcTimeoutMs(
        int timeoutMs);

signals:
    void encryptCompleted(
        QString requestId,
        QJsonObject envelope);

    void encryptFailed(
        QString requestId,
        QString reason);

    void decryptCompleted(
        QString requestId,
        QString plaintext);

    void decryptFailed(
        QString requestId,
        QString reason);

private:
    QJsonObject rpc(
        const QString& method,
        const QJsonObject& params);

    bool ensureConnected();

    bool startLocalCryptoService();

    QString locateServiceScript() const;

    bool writeRequest(
        const QByteArray& payload);

    QJsonObject readResponse(const QString& expectedId = {});

private:
    QTcpSocket m_socket;
    QProcess*  m_serviceProcess = nullptr;

    QString m_lastError;

    int m_rpcTimeoutMs = 5000;

    QString m_serviceHost =
        QStringLiteral("127.0.0.1");

    int m_servicePort = 54231;

    bool m_serviceStarted = false;
};
