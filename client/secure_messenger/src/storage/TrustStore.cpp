#include "TrustStore.h"

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>

TrustStore::TrustStore(QObject* parent)
    : QObject(parent)
{
    const QString dataDir =
        QStandardPaths::writableLocation(
            QStandardPaths::AppLocalDataLocation);

    QDir().mkpath(dataDir);

    m_storagePath =
        dataDir + QStringLiteral("/trust_store.json");

    loadFromDisk();
}

void TrustStore::loadFromDisk()
{
    QFile file(m_storagePath);

    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }

    const auto doc =
        QJsonDocument::fromJson(file.readAll());

    if (!doc.isObject()) {
        return;
    }

    const auto root = doc.object();

    for (auto it = root.begin(); it != root.end(); ++it) {
        const std::string userId = it.key().toStdString();
        const QJsonObject entry  = it.value().toObject();

        m_fingerprints[userId] = entry.value("fingerprint").toString().toStdString();
        m_verified[userId]     = entry.value("verified").toBool(false);
    }
}

void TrustStore::saveToDisk() const
{
    QJsonObject root;

    for (const auto& [userId, fingerprint] : m_fingerprints) {
        QJsonObject entry;
        entry["fingerprint"] = QString::fromStdString(fingerprint);

        auto vit = m_verified.find(userId);
        entry["verified"] = (vit != m_verified.end()) ? vit->second : false;

        root[QString::fromStdString(userId)] = entry;
    }

    QFile file(m_storagePath);

    if (!file.open(
            QIODevice::WriteOnly |
            QIODevice::Truncate)) {
        return;
    }

    file.write(
        QJsonDocument(root).toJson(
            QJsonDocument::Compact));
}

bool TrustStore::verifyIdentity(
    const QString& userId,
    const QString& fingerprint)
{
    const std::string key = userId.toStdString();
    const std::string fp  = fingerprint.toStdString();

    auto it = m_fingerprints.find(key);

    // TOFU: first-seen fingerprint becomes the pin for this identity.
    if (it == m_fingerprints.end() || it->second.empty()) {
        m_fingerprints[key] = fp;
        m_verified[key]     = true;

        saveToDisk();

        emit fingerprintPinned(userId, fingerprint);
        return true;
    }

    if (it->second != fp) {
        m_verified[key] = false;

        saveToDisk();

        emit fingerprintMismatch(
            userId,
            QString::fromStdString(it->second),
            fingerprint);

        return false;
    }

    return true;
}

QString TrustStore::pinnedFingerprint(
    const QString& userId) const
{
    auto it = m_fingerprints.find(userId.toStdString());
    if (it == m_fingerprints.end()) return {};
    return QString::fromStdString(it->second);
}

bool TrustStore::isVerified(
    const QString& userId) const
{
    auto it = m_verified.find(userId.toStdString());
    if (it == m_verified.end()) return false;
    return it->second;
}
