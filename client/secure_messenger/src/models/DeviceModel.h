#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QDateTime>

class DeviceModel : public QObject
{
    Q_OBJECT

    Q_PROPERTY(QString deviceId READ deviceId CONSTANT)
    Q_PROPERTY(QString deviceName READ deviceName WRITE setDeviceName NOTIFY deviceChanged)
    Q_PROPERTY(bool verified READ verified WRITE setVerified NOTIFY verificationChanged)
    Q_PROPERTY(QDateTime lastSeen READ lastSeen WRITE setLastSeen NOTIFY deviceChanged)

public:
    explicit DeviceModel(QObject* parent = nullptr);

    QString deviceId() const;

    QString deviceName() const;
    void setDeviceName(const QString& name);

    QByteArray identityKey() const;
    void setIdentityKey(const QByteArray& key);

    QByteArray pqIdentityKey() const;
    void setPQIdentityKey(const QByteArray& key);

    bool verified() const;
    void setVerified(bool verified);

    QDateTime lastSeen() const;
    void setLastSeen(const QDateTime& timestamp);

signals:
    void deviceChanged();
    void verificationChanged();

private:
    QString m_deviceId;
    QString m_deviceName;

    QByteArray m_identityKey;
    QByteArray m_pqIdentityKey;

    bool m_verified = false;

    QDateTime m_lastSeen;
};