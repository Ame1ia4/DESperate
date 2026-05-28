#include "TrustStore.h"

TrustStore::TrustStore(QObject* parent)
    : QObject(parent)
{
}

bool TrustStore::verifyIdentity(
    const QString& userId,
    const QString& fingerprint)
{
    const QString existing =
        m_fingerprints.value(userId);

    // TOFU
    if (existing.isEmpty()) {
        m_fingerprints[userId] = fingerprint;
        m_verified[userId] = true;

        emit fingerprintPinned(userId, fingerprint);
        return true;
    }

    if (existing != fingerprint) {
        m_verified[userId] = false;

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