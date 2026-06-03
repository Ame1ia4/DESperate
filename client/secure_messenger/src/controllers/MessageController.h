
#pragma once

#include <QObject>
#include <QString>
#include <QHash>
#include <QJsonObject>

class ApiClient;
class CryptoServiceClient;
class LocalMessageStore;
class MessageModel;
class TrustStore;
class SessionStore;
class ConversationController;

struct PendingMessage;
struct DecryptedMessage;

struct PendingMessage
{
    QString requestId;

    QString conversationId;

    QString recipientDeviceId;

    QByteArray plaintext;

    bool forwarded = false;
};

class MessageController : public QObject
{
    Q_OBJECT

public:
    explicit MessageController(
        ApiClient* api,
        CryptoServiceClient* crypto,
        LocalMessageStore* store,
        MessageModel* model,
        ConversationController* conversations,
        TrustStore* trust,
        SessionStore* sessions,
        QObject* parent = nullptr);

public slots:
    Q_INVOKABLE void sendText(
        const QString& conversationId,
        const QString& text,
        bool forwarded = false);

    Q_INVOKABLE void deleteMessage(const QString& messageId);
    Q_INVOKABLE void revokeMessage(const QString& messageId, const QString& recipientDeviceId);
    Q_INVOKABLE void forwardMessage(const QString& toUsername, const QString& plaintext);
    Q_INVOKABLE void downloadMessage(const QString& messageId, const QString& plaintext);
    Q_INVOKABLE QString ciphertextForMessage(const QString& messageId) const;
    Q_INVOKABLE void copyCiphertext(const QString& messageId);
    Q_INVOKABLE void copyMerkleRoot(const QString& messageId);

    void sendMessage(
        QString conversationId,
        QString recipientDeviceId,
        QByteArray plaintext,
        bool forwarded = false);

    void receiveEnvelope(
        QJsonObject envelope);

    void pullAndProcessMessages(
        QString deviceId);

    // Fetch historical messages for a conversation and decrypt them.
    void fetchConversationHistory(const QString& conversationId);

signals:
    void messageSent();

    void messageReceived();

    void messageSendFailed(
        QString reason);

    void messageReceiveFailed(
        QString reason);

    void messageDownloaded(QString path);
    void messageDownloadFailed(QString reason);
    void messageRevokeSucceeded();
    void messageRevokeFailed();
    void ciphertextCopied();
    void ciphertextCopyFailed();
    void forwardInitiated(QString toUsername);
    void merkleRootCopied(QString merkleRoot);
    void merkleRootPending(QString messageId);

private slots:
    void handleEncryptCompleted(
        QString requestId,
        QJsonObject envelope);

    void handleEncryptFailed(
        QString requestId,
        QString reason);

    void handleDecryptCompleted(
        QString requestId,
        QString plaintext);

    void handleDecryptFailed(
        QString requestId,
        QString reason);

private:
    ApiClient* m_api = nullptr;

    CryptoServiceClient* m_crypto = nullptr;

    LocalMessageStore* m_store = nullptr;

    MessageModel* m_model = nullptr;

    ConversationController* m_conversations =
        nullptr;

    TrustStore* m_trust = nullptr;

    SessionStore* m_sessions = nullptr;

    QHash<QString, PendingMessage>
        m_pendingMessages;

    QHash<QString, QJsonObject>
        m_pendingDecryptions;

    QHash<QString, QString>
        m_pendingForwards;
};
