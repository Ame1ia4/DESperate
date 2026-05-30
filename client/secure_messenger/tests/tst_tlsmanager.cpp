#include <QtTest>
#include <QSignalSpy>
#include <QSslConfiguration>
#include <QSslSocket>
#include "TLSManager.h"
#include "TrustStore.h"

class TestTLSManager : public QObject
{
    Q_OBJECT

private slots:
    void notConnectedInitially();
    void invalidCaPath_emitsConnectionFailed();
    void defaultConfig_requiresTls13();
    void defaultConfig_requiresPeerVerification();
    void setPinnedHash_doesNotCrash();
};

void TestTLSManager::notConnectedInitially()
{
    TrustStore ts(QStringLiteral("/nonexistent/ca.pem"));
    TLSManager mgr(&ts);
    QVERIFY(!mgr.isConnected());
}

// When TrustStore has a non-empty but nonexistent path, isValid() returns false,
// so TLSManager sets m_initError in the constructor. connectToHost() then emits
// connectionFailed synchronously before touching any network.
void TestTLSManager::invalidCaPath_emitsConnectionFailed()
{
    TrustStore ts(QStringLiteral("/nonexistent/ca.pem"));
    TLSManager mgr(&ts);
    QSignalSpy spy(&mgr, &TLSManager::connectionFailed);
    mgr.connectToHost(QStringLiteral("example.com"), 443);
    QCOMPARE(spy.count(), 1);
    QVERIFY(!spy.at(0).at(0).toString().isEmpty());
}

void TestTLSManager::defaultConfig_requiresTls13()
{
    const QSslConfiguration cfg = TLSManager::defaultConfig();
    QCOMPARE(cfg.protocol(), QSsl::TlsV1_3OrLater);
}

void TestTLSManager::defaultConfig_requiresPeerVerification()
{
    const QSslConfiguration cfg = TLSManager::defaultConfig();
    QCOMPARE(cfg.peerVerifyMode(), QSslSocket::VerifyPeer);
}

void TestTLSManager::setPinnedHash_doesNotCrash()
{
    TrustStore ts(QString{});
    TLSManager mgr(&ts);
    mgr.setPinnedPublicKeyHash(QByteArray(32, '\xAB'));
}

QTEST_MAIN(TestTLSManager)
#include "tst_tlsmanager.moc"
