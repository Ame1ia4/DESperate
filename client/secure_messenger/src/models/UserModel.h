#pragma once

#include <QObject>
#include <QString>
#include <QDateTime>
#include <QByteArray>

enum class TrustLevel
{
    Unknown,
    TOFU,
    Verified,
    Revoked,
    Compromised
};

class UserModel : public QObject
{
    Q_OBJECT

    Q_PROPERTY(QString userId READ userId CONSTANT)
    Q_PROPERTY(QString username READ username WRITE setUsername NOTIFY usernameChanged)

    Q_PROPERTY(QString identityKeyFingerprint
                   READ identityKeyFingerprint
                       NOTIFY keysChanged)

    Q_PROPERTY(QString pqIdentityFingerprint
                   READ pqIdentityFingerprint
                       NOTIFY keysChanged)

    Q_PROPERTY(bool verified
                   READ verified
                       WRITE setVerified
                           NOTIFY verificationChanged)

    Q_PROPERTY(QDateTime lastSeen
                   READ lastSeen
                       WRITE setLastSeen
                           NOTIFY lastSeenChanged)

public:
    explicit UserModel(QObject* parent = nullptr);

    QString userId() const;

    QString username() const;
    void setUsername(const QString& username);

    QString identityKeyFingerprint() const;

    QString pqIdentityFingerprint() const;

    bool verified() const;
    void setVerified(bool verified);

    QDateTime lastSeen() const;
    void setLastSeen(const QDateTime& timestamp);

    TrustLevel trustLevel() const;
    void setTrustLevel(TrustLevel level);

    QByteArray identityPublicKey() const;
    QByteArray pqIdentityPublicKey() const;

    QByteArray signedPreKey() const;
    QByteArray pqSignedPreKey() const;

    QString activeDeviceId() const;

signals:
    void usernameChanged();
    void keysChanged();
    void verificationChanged();
    void lastSeenChanged();

private:
    QString m_userId;
    QString m_username;

    QByteArray m_identityPublicKey;
    QByteArray m_pqIdentityPublicKey;

    QByteArray m_signedPreKey;
    QByteArray m_pqSignedPreKey;

    QString m_identityFingerprint;
    QString m_pqFingerprint;

    QString m_activeDeviceId;

    bool m_verified = false;

    TrustLevel m_trustLevel = TrustLevel::Unknown;

    QDateTime m_lastSeen;
};