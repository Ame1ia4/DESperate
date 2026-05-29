#ifndef TLSMANAGER_H
#define TLSMANAGER_H

#include <QSslConfiguration>
#include <QString>

class TLSManager
{
public:
    TLSManager() = default;

    // Returns a QSslConfiguration enforcing TLS 1.3 with peer
    // verification using the system CA store.  Pass this to every
    // QNetworkRequest via setSslConfiguration().
    static QSslConfiguration defaultConfig();

    // Same as defaultConfig() but also pins the PEM certificate at
    // pemPath.  Use this to pin the project server's certificate for
    // an additional layer of TOFU at the transport level.
    static QSslConfiguration pinnedConfig(const QString& pemPath);
};

#endif // TLSMANAGER_H
