#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QDateTime>
#include <string>
#include <unordered_map>

struct SessionState
{
    QString sessionId;

    QString localDeviceId;
    QString remoteDeviceId;

    QByteArray rootKey;

    QByteArray sendChainKey;
    QByteArray receiveChainKey;

    quint64 sendNonceCounter = 0;
    quint64 receiveNonceCounter = 0;

    QDateTime establishedAt;
    QDateTime lastUsedAt;
};

class SessionStore : public QObject
{
    Q_OBJECT

public:
    explicit SessionStore(QObject* parent = nullptr);

    bool hasSession(const QString& remoteDeviceId) const;

    SessionState session(
        const QString& remoteDeviceId) const;

    void storeSession(const SessionState& state);

    void incrementSendCounter(
        const QString& remoteDeviceId);

private:
    std::unordered_map<std::string, SessionState> m_sessions;
};