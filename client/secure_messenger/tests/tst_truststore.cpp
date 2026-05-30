#include <QtTest>
#include <QTemporaryFile>
#include "TrustStore.h"

class TestTrustStore : public QObject
{
    Q_OBJECT

private slots:
    void emptyPath_isInvalid();
    void nonexistentPath_isInvalid();
    void existingPath_isValid();
    void caBundlePath_returnsStoredPath();
};

void TestTrustStore::emptyPath_isInvalid()
{
    TrustStore ts(QString{});
    QVERIFY(!ts.isValid());
}

void TestTrustStore::nonexistentPath_isInvalid()
{
    TrustStore ts(QStringLiteral("/nonexistent/path/that/cannot/exist/ca.pem"));
    QVERIFY(!ts.isValid());
}

void TestTrustStore::existingPath_isValid()
{
    QTemporaryFile f;
    QVERIFY(f.open());
    TrustStore ts(f.fileName());
    QVERIFY(ts.isValid());
}

void TestTrustStore::caBundlePath_returnsStoredPath()
{
    const QString path = QStringLiteral("/some/path/ca.pem");
    TrustStore ts(path);
    QCOMPARE(ts.caBundlePath(), path);
}

QTEST_MAIN(TestTrustStore)
#include "tst_truststore.moc"
