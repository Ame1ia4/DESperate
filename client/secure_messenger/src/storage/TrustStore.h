#pragma once

#include <QObject>
#include <QString>
#include <string>
#include <unordered_map>

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
    void loadFromDisk();
    void saveToDisk() const;

    QString m_storagePath;
    // Maps userId (std::string) to pinned fingerprint (std::string) — TOFU model
    std::unordered_map<std::string, std::string> m_fingerprints;
    std::unordered_map<std::string, bool> m_verified;
};