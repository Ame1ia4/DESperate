#include "SessionStore.h"

SessionStore::SessionStore(QObject* parent)
    : QObject(parent)
{
}

bool SessionStore::hasSession(
    const QString& remoteDeviceId) const
{
    return m_sessions.count(remoteDeviceId.toStdString()) > 0;
}

SessionState SessionStore::session(
    const QString& remoteDeviceId) const
{
    auto it = m_sessions.find(remoteDeviceId.toStdString());
    if (it != m_sessions.end()) return it->second;
    return {};
}

void SessionStore::storeSession(
    const SessionState& state)
{
    m_sessions[state.remoteDeviceId.toStdString()] = state;
}

void SessionStore::incrementSendCounter(
    const QString& remoteDeviceId)
{
    auto it = m_sessions.find(remoteDeviceId.toStdString());
    if (it == m_sessions.end()) {
        return;
    }

    it->second.sendNonceCounter++;
    it->second.lastUsedAt = QDateTime::currentDateTimeUtc();
}
