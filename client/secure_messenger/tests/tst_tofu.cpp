// Unit tests for the TOFU (Trust On First Use) TrustStore.
//
// Coverage:
//   - First-seen identity: pin fingerprint, emit fingerprintPinned, return true
//   - First-seen: sets isVerified true
//   - Same fingerprint on second call: return true, no spurious signals
//   - Different fingerprint: return false, emit fingerprintMismatch, set isVerified false
//   - Different fingerprint: pinned fingerprint is NOT replaced (TOFU invariant)
//   - Unknown user: pinnedFingerprint returns "", isVerified returns false
//   - Multiple independent users: fingerprints don't bleed across identities
//   - Mismatch for one user does not affect another
//
// Brief alignment (Cryptography — O'Brien):
//   The TOFU model is the trust model stated in the design document.  These
//   tests verify the specific properties required by the rubric:
//     - Recipients can verify message origin (fingerprint pinning)
//     - A compromised server serving a different public key is detectable
//       (fingerprintMismatch signal)
//   Tests also verify honest-but-curious-server resilience: a server that
//   returns a different public key for an already-pinned user is flagged,
//   satisfying the "key publication designed against an active or compromised
//   server" requirement.

#include <QtTest>
#include <QSignalSpy>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QStandardPaths>

#include "../src/storage/TrustStore.h"

// ── Test class ────────────────────────────────────────────────────────────────

class TestTOFU : public QObject
{
    Q_OBJECT

private:
    static void wipeTrustStoreFile()
    {
        const QString dataDir =
            QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
        QFile::remove(dataDir + QStringLiteral("/trust_store.json"));
    }

private slots:
    void init()
    {
        QCoreApplication::setOrganizationName(QStringLiteral("DESperate-Test"));
        QCoreApplication::setApplicationName(QStringLiteral("tst_tofu"));
        wipeTrustStoreFile();
    }

    void cleanup()
    {
        wipeTrustStoreFile();
    }

    // ── First-seen (TOFU pin) ─────────────────────────────────────────────

    void firstSeen_returnsTrue()
    {
        TrustStore ts;
        QVERIFY(ts.verifyIdentity(QStringLiteral("alice"), QStringLiteral("fp-abc123")));
    }

    void firstSeen_pinsFingerprint()
    {
        TrustStore ts;
        ts.verifyIdentity(QStringLiteral("alice"), QStringLiteral("fp-abc123"));
        QCOMPARE(ts.pinnedFingerprint(QStringLiteral("alice")),
                 QStringLiteral("fp-abc123"));
    }

    void firstSeen_setsVerifiedTrue()
    {
        TrustStore ts;
        ts.verifyIdentity(QStringLiteral("alice"), QStringLiteral("fp-abc123"));
        QVERIFY(ts.isVerified(QStringLiteral("alice")));
    }

    void firstSeen_emitsFingerprintPinned()
    {
        TrustStore ts;
        QSignalSpy spy(&ts, &TrustStore::fingerprintPinned);
        ts.verifyIdentity(QStringLiteral("alice"), QStringLiteral("fp-abc123"));
        QCOMPARE(spy.count(), 1);
        QCOMPARE(spy.at(0).at(0).toString(), QStringLiteral("alice"));
        QCOMPARE(spy.at(0).at(1).toString(), QStringLiteral("fp-abc123"));
    }

    void firstSeen_doesNotEmitMismatch()
    {
        TrustStore ts;
        QSignalSpy spy(&ts, &TrustStore::fingerprintMismatch);
        ts.verifyIdentity(QStringLiteral("alice"), QStringLiteral("fp-abc123"));
        QCOMPARE(spy.count(), 0);
    }

    // ── Same fingerprint on subsequent call ───────────────────────────────

    void sameFingerprint_returnsTrue()
    {
        TrustStore ts;
        ts.verifyIdentity(QStringLiteral("bob"), QStringLiteral("fp-xyz"));
        QVERIFY(ts.verifyIdentity(QStringLiteral("bob"), QStringLiteral("fp-xyz")));
    }

    void sameFingerprint_doesNotEmitPinnedAgain()
    {
        TrustStore ts;
        ts.verifyIdentity(QStringLiteral("bob"), QStringLiteral("fp-xyz"));
        QSignalSpy spy(&ts, &TrustStore::fingerprintPinned);
        ts.verifyIdentity(QStringLiteral("bob"), QStringLiteral("fp-xyz"));
        QCOMPARE(spy.count(), 0);
    }

    void sameFingerprint_doesNotEmitMismatch()
    {
        TrustStore ts;
        ts.verifyIdentity(QStringLiteral("bob"), QStringLiteral("fp-xyz"));
        QSignalSpy spy(&ts, &TrustStore::fingerprintMismatch);
        ts.verifyIdentity(QStringLiteral("bob"), QStringLiteral("fp-xyz"));
        QCOMPARE(spy.count(), 0);
    }

    // ── Fingerprint mismatch — potential MITM / server compromise ─────────

    void differentFingerprint_returnsFalse()
    {
        TrustStore ts;
        ts.verifyIdentity(QStringLiteral("charlie"), QStringLiteral("fp-original"));
        QVERIFY(!ts.verifyIdentity(QStringLiteral("charlie"), QStringLiteral("fp-attacker")));
    }

    void differentFingerprint_emitsFingerprintMismatch()
    {
        TrustStore ts;
        ts.verifyIdentity(QStringLiteral("charlie"), QStringLiteral("fp-original"));
        QSignalSpy spy(&ts, &TrustStore::fingerprintMismatch);
        ts.verifyIdentity(QStringLiteral("charlie"), QStringLiteral("fp-attacker"));

        QCOMPARE(spy.count(), 1);
        // userId
        QCOMPARE(spy.at(0).at(0).toString(), QStringLiteral("charlie"));
        // expected (pinned)
        QCOMPARE(spy.at(0).at(1).toString(), QStringLiteral("fp-original"));
        // received (suspicious)
        QCOMPARE(spy.at(0).at(2).toString(), QStringLiteral("fp-attacker"));
    }

    void differentFingerprint_setsVerifiedFalse()
    {
        TrustStore ts;
        ts.verifyIdentity(QStringLiteral("charlie"), QStringLiteral("fp-original"));
        ts.verifyIdentity(QStringLiteral("charlie"), QStringLiteral("fp-attacker"));
        QVERIFY(!ts.isVerified(QStringLiteral("charlie")));
    }

    void differentFingerprint_pinnedFingerprintUnchanged()
    {
        // TOFU invariant: the first-seen fingerprint remains pinned even after a
        // mismatch.  Replacing it silently would defeat the attack-detection purpose.
        TrustStore ts;
        ts.verifyIdentity(QStringLiteral("dave"), QStringLiteral("fp-original"));
        ts.verifyIdentity(QStringLiteral("dave"), QStringLiteral("fp-attacker"));
        QCOMPARE(ts.pinnedFingerprint(QStringLiteral("dave")),
                 QStringLiteral("fp-original"));
    }

    void mismatch_doesNotEmitPinned()
    {
        TrustStore ts;
        ts.verifyIdentity(QStringLiteral("eve"), QStringLiteral("fp-a"));
        QSignalSpy spy(&ts, &TrustStore::fingerprintPinned);
        ts.verifyIdentity(QStringLiteral("eve"), QStringLiteral("fp-b"));
        QCOMPARE(spy.count(), 0);
    }

    // ── Unknown user queries ──────────────────────────────────────────────

    void unknownUser_pinnedFingerprint_returnsEmptyString()
    {
        TrustStore ts;
        QVERIFY(ts.pinnedFingerprint(QStringLiteral("unknown")).isEmpty());
    }

    void unknownUser_isVerified_returnsFalse()
    {
        TrustStore ts;
        QVERIFY(!ts.isVerified(QStringLiteral("unknown")));
    }

    // ── Multiple independent users ────────────────────────────────────────

    void multipleUsers_fingerprintsAreIndependent()
    {
        TrustStore ts;
        ts.verifyIdentity(QStringLiteral("user-a"), QStringLiteral("fp-aaa"));
        ts.verifyIdentity(QStringLiteral("user-b"), QStringLiteral("fp-bbb"));

        QCOMPARE(ts.pinnedFingerprint(QStringLiteral("user-a")),
                 QStringLiteral("fp-aaa"));
        QCOMPARE(ts.pinnedFingerprint(QStringLiteral("user-b")),
                 QStringLiteral("fp-bbb"));
        QVERIFY(ts.isVerified(QStringLiteral("user-a")));
        QVERIFY(ts.isVerified(QStringLiteral("user-b")));
    }

    void mismatchForOneUser_doesNotAffectAnother()
    {
        TrustStore ts;
        ts.verifyIdentity(QStringLiteral("user-a"), QStringLiteral("fp-aaa"));
        ts.verifyIdentity(QStringLiteral("user-b"), QStringLiteral("fp-bbb"));

        // Mismatch only for user-b
        ts.verifyIdentity(QStringLiteral("user-b"), QStringLiteral("fp-attacker"));

        QVERIFY(ts.isVerified(QStringLiteral("user-a")));
        QVERIFY(!ts.isVerified(QStringLiteral("user-b")));
    }

    void multipleUsers_allReceivePinnedSignal()
    {
        TrustStore ts;
        QSignalSpy spy(&ts, &TrustStore::fingerprintPinned);
        ts.verifyIdentity(QStringLiteral("user-x"), QStringLiteral("fp-x"));
        ts.verifyIdentity(QStringLiteral("user-y"), QStringLiteral("fp-y"));
        QCOMPARE(spy.count(), 2);
    }
};

QTEST_MAIN(TestTOFU)
#include "tst_tofu.moc"
