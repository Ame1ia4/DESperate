#pragma once

#include <QString>

class TrustStore
{
public:
    explicit TrustStore(const QString& caBundlePath);

    const QString& caBundlePath() const;
    bool isValid() const;

private:
    QString m_caBundlePath;
};
