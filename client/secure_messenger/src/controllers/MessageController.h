#pragma once

#include <QObject>
#include <QJsonObject>

class ApiClient;
class CryptoServiceClient;
class LocalMessageStore;
class MessageModel;
class TrustStore;

class MessageController : public QObject
{
    Q_OBJECT

public:
    explicit MessageController(
        ApiClient* api,
        CryptoServiceClient* crypto,
        LocalMessageStore* store,
        MessageModel* model,
        TrustStore* trust,
        QObject* parent = nullptr
        );

    Q_INVOKABLE void sendMessage(
        QString conversationId,
        QString recipientDeviceId,
        QString plaintext
        );
    Q_INVOKABLE void receiveEnvelope(
        QJsonObject envelope
        );

signals:
    void messageSendFailed(QString reason);
    void messageSent();
    void messageReceiveFailed(QString reason);
    void messageReceived();

private:
    ApiClient* m_api;
    CryptoServiceClient* m_crypto;
    LocalMessageStore* m_store;
    MessageModel* m_model;
    TrustStore* m_trust;
};