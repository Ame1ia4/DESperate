#include "TrustStore.h"

#include <QFileInfo>

TrustStore::TrustStore(const QString& caBundlePath)
    : m_caBundlePath(caBundlePath)
{
}

const QString& TrustStore::caBundlePath() const
{
    return m_caBundlePath;
}

bool TrustStore::isValid() const
{
    return !m_caBundlePath.isEmpty() && QFileInfo::exists(m_caBundlePath);
}
