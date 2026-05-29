#include "UserModel.h"

#include <QUuid>

UserModel::UserModel(QObject* parent)
    : QObject(parent)
    , m_userId(QUuid::createUuid().toString(QUuid::WithoutBraces))
{
}

QString UserModel::userId() const
{
    return m_userId;
}

QString UserModel::username() const
{
    return m_username;
}

void UserModel::setUsername(const QString& username)
{
    if (m_username == username) {
        return;
    }

    m_username = username;
    emit usernameChanged();
}

QString UserModel::identityKeyFingerprint() const
{
    return m_identityFingerprint;
}

QString UserModel::pqIdentityFingerprint() const
{
    return m_pqFingerprint;
}

bool UserModel::verified() const
{
    return m_verified;
}

void UserModel::setVerified(bool verified)
{
    if (m_verified == verified) {
        return;
    }

    m_verified = verified;

    if (verified) {
        m_trustLevel = TrustLevel::Verified;
    }

    emit verificationChanged();
}

QDateTime UserModel::lastSeen() const
{
    return m_lastSeen;
}

void UserModel::setLastSeen(const QDateTime& timestamp)
{
    if (m_lastSeen == timestamp) {
        return;
    }

    m_lastSeen = timestamp;
    emit lastSeenChanged();
}

TrustLevel UserModel::trustLevel() const
{
    return m_trustLevel;
}

void UserModel::setTrustLevel(TrustLevel level)
{
    if (m_trustLevel == level) {
        return;
    }

    m_trustLevel = level;

    if (level == TrustLevel::Verified) {
        m_verified = true;
    }

    emit verificationChanged();
}

QByteArray UserModel::identityPublicKey() const
{
    return m_identityPublicKey;
}

QByteArray UserModel::pqIdentityPublicKey() const
{
    return m_pqIdentityPublicKey;
}

QByteArray UserModel::signedPreKey() const
{
    return m_signedPreKey;
}

QByteArray UserModel::pqSignedPreKey() const
{
    return m_pqSignedPreKey;
}

QString UserModel::activeDeviceId() const
{
    return m_activeDeviceId;
}