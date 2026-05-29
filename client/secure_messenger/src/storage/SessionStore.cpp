#include "SessionStore.h"

SessionStore::SessionStore(QObject* parent)
    : QObject(parent)
{
}

bool SessionStore::hasSession(
    const QString& remoteDeviceId) const
{
    return m_sessions.contains(remoteDeviceId);
}

SessionState SessionStore::session(
    const QString& remoteDeviceId) const
{
    return m_sessions.value(remoteDeviceId);
}

void SessionStore::storeSession(
    const SessionState& state)
{
    m_sessions[state.remoteDeviceId] = state;
}

void SessionStore::incrementSendCounter(
    const QString& remoteDeviceId)
{
    if (!m_sessions.contains(remoteDeviceId)) {
        return;
    }

    auto& state = m_sessions[remoteDeviceId];

    state.sendNonceCounter++;
    state.lastUsedAt = QDateTime::currentDateTimeUtc();
}