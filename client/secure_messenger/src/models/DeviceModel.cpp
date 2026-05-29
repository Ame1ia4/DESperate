#include "DeviceModel.h"

#include <QUuid>

DeviceModel::DeviceModel(QObject* parent)
    : QObject(parent)
    , m_deviceId(QUuid::createUuid().toString(QUuid::WithoutBraces))
{
}

QString DeviceModel::deviceId() const
{
    return m_deviceId;
}

QString DeviceModel::deviceName() const
{
    return m_deviceName;
}

void DeviceModel::setDeviceName(const QString& name)
{
    if (m_deviceName == name) {
        return;
    }

    m_deviceName = name;
    emit deviceChanged();
}

QByteArray DeviceModel::identityKey() const
{
    return m_identityKey;
}

void DeviceModel::setIdentityKey(const QByteArray& key)
{
    m_identityKey = key;
    emit deviceChanged();
}

QByteArray DeviceModel::pqIdentityKey() const
{
    return m_pqIdentityKey;
}

void DeviceModel::setPQIdentityKey(const QByteArray& key)
{
    m_pqIdentityKey = key;
    emit deviceChanged();
}

bool DeviceModel::verified() const
{
    return m_verified;
}

void DeviceModel::setVerified(bool verified)
{
    if (m_verified == verified) {
        return;
    }

    m_verified = verified;
    emit verificationChanged();
}

QDateTime DeviceModel::lastSeen() const
{
    return m_lastSeen;
}

void DeviceModel::setLastSeen(const QDateTime& timestamp)
{
    m_lastSeen = timestamp;
    emit deviceChanged();
}