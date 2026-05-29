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

    for (auto it = root.begin();
         it != root.end(); ++it) {

        const QString userId = it.key();
        const QJsonObject entry =
            it.value().toObject();

        m_fingerprints[userId] =
            entry.value("fingerprint").toString();

        m_verified[userId] =
            entry.value("verified").toBool(false);
    }
}

void TrustStore::saveToDisk() const
{
    QJsonObject root;

    for (auto it = m_fingerprints.cbegin();
         it != m_fingerprints.cend(); ++it) {

        QJsonObject entry;
        entry["fingerprint"] = it.value();
        entry["verified"] =
            m_verified.value(it.key(), false);

        root[it.key()] = entry;
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
    const QString existing =
        m_fingerprints.value(userId);

    // TOFU: first-seen fingerprint becomes the pin for this identity.
    if (existing.isEmpty()) {
        m_fingerprints[userId] = fingerprint;
        m_verified[userId] = true;

        saveToDisk();

        emit fingerprintPinned(userId, fingerprint);
        return true;
    }

    if (existing != fingerprint) {
        m_verified[userId] = false;

        saveToDisk();

        emit fingerprintMismatch(
            userId,
            existing,
            fingerprint);

        return false;
    }

    return true;
}

QString TrustStore::pinnedFingerprint(
    const QString& userId) const
{
    return m_fingerprints.value(userId);
}

bool TrustStore::isVerified(
    const QString& userId) const
{
    return m_verified.value(userId);
}