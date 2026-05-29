#include "SessionModel.h"

#include <QUuid>

SessionModel::SessionModel(QObject* parent)
    : QObject(parent)
    , m_sessionId(QUuid::createUuid().toString(QUuid::WithoutBraces))
{
}

QString SessionModel::sessionId() const
{
    return m_sessionId;
}

QString SessionModel::remoteDeviceId() const
{
    return m_remoteDeviceId;
}

void SessionModel::setRemoteDeviceId(const QString& id)
{
    m_remoteDeviceId = id;
    emit sessionChanged();
}

bool SessionModel::established() const
{
    return m_established;
}

void SessionModel::setEstablished(bool established)
{
    m_established = established;
    emit sessionChanged();
}

bool SessionModel::verified() const
{
    return m_verified;
}

void SessionModel::setVerified(bool verified)
{
    m_verified = verified;
    emit sessionChanged();
}

QDateTime SessionModel::establishedAt() const
{
    return m_establishedAt;
}

void SessionModel::setEstablishedAt(const QDateTime& timestamp)
{
    m_establishedAt = timestamp;
    emit sessionChanged();
}