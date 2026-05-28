#pragma once

#include <QObject>
#include <QString>
#include <QDateTime>

class SessionModel : public QObject
{
    Q_OBJECT

    Q_PROPERTY(QString sessionId READ sessionId CONSTANT)
    Q_PROPERTY(QString remoteDeviceId READ remoteDeviceId CONSTANT)
    Q_PROPERTY(bool established READ established NOTIFY sessionChanged)
    Q_PROPERTY(bool verified READ verified NOTIFY sessionChanged)
    Q_PROPERTY(QDateTime establishedAt READ establishedAt NOTIFY sessionChanged)

public:
    explicit SessionModel(QObject* parent = nullptr);

    QString sessionId() const;

    QString remoteDeviceId() const;
    void setRemoteDeviceId(const QString& id);

    bool established() const;
    void setEstablished(bool established);

    bool verified() const;
    void setVerified(bool verified);

    QDateTime establishedAt() const;
    void setEstablishedAt(const QDateTime& timestamp);

signals:
    void sessionChanged();

private:
    QString m_sessionId;
    QString m_remoteDeviceId;

    bool m_established = false;
    bool m_verified = false;

    QDateTime m_establishedAt;
};