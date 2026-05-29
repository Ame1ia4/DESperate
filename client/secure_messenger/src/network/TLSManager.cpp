#include "TLSManager.h"

#include <QFile>
#include <QSslCertificate>
#include <QSslSocket>

QSslConfiguration TLSManager::defaultConfig()
{
    QSslConfiguration ssl =
        QSslConfiguration::defaultConfiguration();

    ssl.setProtocol(QSsl::TlsV1_3);
    ssl.setPeerVerifyMode(QSslSocket::VerifyPeer);

    return ssl;
}

QSslConfiguration TLSManager::pinnedConfig(
    const QString& pemPath)
{
    QSslConfiguration ssl = defaultConfig();

    QFile file(pemPath);

    if (!file.open(QIODevice::ReadOnly)) {
        return ssl;
    }

    const QList<QSslCertificate> certs =
        QSslCertificate::fromDevice(
            &file, QSsl::Pem);

    if (!certs.isEmpty()) {
        ssl.setCaCertificates(certs);
    }

    return ssl;
}
