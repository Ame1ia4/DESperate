#pragma once

#include <QObject>
#include <QString>
#include <QHash>

class TrustStore : public QObject
{
    Q_OBJECT

public:
    explicit TrustStore(QObject* parent = nullptr);

    bool verifyIdentity(
        const QString& userId,
        const QString& fingerprint);

    QString pinnedFingerprint(
        const QString& userId) const;

    bool isVerified(const QString& userId) const;

signals:
    void fingerprintPinned(
        QString userId,
        QString fingerprint);

    void fingerprintMismatch(
        QString userId,
        QString expected,
        QString received);

private:
    QHash<QString, QString> m_fingerprints;
    QHash<QString, bool> m_verified;
};