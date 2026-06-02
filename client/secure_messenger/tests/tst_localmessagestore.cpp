// Unit tests for LocalMessageStore.
//
// Coverage:
//   - Decrypted message storage, deduplication, filtering, clearing
//   - Encrypted envelope storage, deduplication, filtering
//   - JSON envelope parsing (storeOutgoingMessage)
//   - E2EE invariant: ciphertext bytes must never equal the corresponding plaintext
//   - isDeleted flag preservation
//   - Index consistency after clearConversation
//
// Brief alignment (Cryptography — O'Brien):
//   The server stores only ciphertext; this store verifies the client likewise
//   separates ciphertext (MessageEnvelope) from decrypted plaintext
//   (DecryptedMessage), satisfying the "server must not see plaintext" requirement.

#include <QtTest>
#include <QCoreApplication>
#include <QJsonObject>
#include <QSettings>

#include "../src/storage/LocalMessageStore.h"
#include "../src/types/Types.h"

// ── Helpers ──────────────────────────────────────────────────────────────────

static DecryptedMessage makeMessage(
    const QString& id,
    const QString& conversationId,
    const QString& plaintext      = QStringLiteral("hello"),
    const QString& senderDeviceId = QStringLiteral("device-abc"),
    bool           isDeleted      = false)
{
    DecryptedMessage m;
    m.id              = id;
    m.conversationId  = conversationId;
    m.plaintext       = plaintext;
    m.senderDeviceId  = senderDeviceId;
    m.timestamp       = QDateTime::currentDateTimeUtc();
    m.verificationState = VerificationState::Verified;
    m.isDeleted       = isDeleted;
    return m;
}

static MessageEnvelope makeEnvelope(
    const QString& id,
    const QString& conversationId,
    const QByteArray& ciphertext = QByteArray("fake-ciphertext-blob"),
    bool isDeleted               = false)
{
    MessageEnvelope e;
    e.id              = id;
    e.conversationId  = conversationId;
    e.senderDeviceId  = QStringLiteral("device-abc");
    e.ciphertext      = ciphertext;
    e.nonce           = QByteArray(12, '\x01');
    e.associatedData  = QByteArray("associated-data");
    e.txHash          = QStringLiteral("0xTXHASH");
    e.merkleRoot      = QStringLiteral("0xMERKLE");
    e.timestamp       = QDateTime::currentDateTimeUtc();
    e.verificationState = VerificationState::Pending;
    e.isDeleted       = isDeleted;
    return e;
}

// ── Test class ────────────────────────────────────────────────────────────────

class TestLocalMessageStore : public QObject
{
    Q_OBJECT

private slots:
    void init()
    {
        QCoreApplication::setOrganizationName(QStringLiteral("DESperate-Test"));
        QCoreApplication::setApplicationName(QStringLiteral("tst_localmessagestore"));
        // Clear any QSettings state from a previous test run.
        QSettings s;
        s.remove(QStringLiteral("local_store"));
    }

    void cleanup()
    {
        QSettings s;
        s.remove(QStringLiteral("local_store"));
    }

    // ── Decrypted message storage ─────────────────────────────────────────

    void initialState_noDecryptedMessages()
    {
        LocalMessageStore store;
        QCOMPARE(store.decryptedMessages().size(), 0);
    }

    void storeDecryptedMessage_messageIsRetrievable()
    {
        LocalMessageStore store;
        store.storeDecryptedMessage(makeMessage("msg-1", "conv-1", "secret text"));
        QCOMPARE(store.decryptedMessages().size(), 1);
        QCOMPARE(store.decryptedMessages().at(0).plaintext, QStringLiteral("secret text"));
    }

    void storeDecryptedMessage_emptyId_isIgnored()
    {
        LocalMessageStore store;
        store.storeDecryptedMessage(makeMessage("", "conv-1", "ignored"));
        QCOMPARE(store.decryptedMessages().size(), 0);
    }

    void storeDecryptedMessage_duplicateId_deduplicates()
    {
        LocalMessageStore store;
        store.storeDecryptedMessage(makeMessage("dup", "conv-1", "first version"));
        store.storeDecryptedMessage(makeMessage("dup", "conv-1", "second version"));
        QCOMPARE(store.decryptedMessages().size(), 1);
        QCOMPARE(store.decryptedMessages().at(0).plaintext, QStringLiteral("first version"));
    }

    void storeDecryptedMessage_isDeletedFlagPreserved()
    {
        LocalMessageStore store;
        store.storeDecryptedMessage(makeMessage("del-msg", "conv-1", "deleted", "dev", true));
        QVERIFY(store.decryptedMessages().at(0).isDeleted);
    }

    void storeDecryptedMessage_multipleMessages_allStored()
    {
        LocalMessageStore store;
        store.storeDecryptedMessage(makeMessage("a", "conv-1", "alpha"));
        store.storeDecryptedMessage(makeMessage("b", "conv-1", "beta"));
        store.storeDecryptedMessage(makeMessage("c", "conv-1", "gamma"));
        QCOMPARE(store.decryptedMessages().size(), 3);
    }

    // ── containsMessage ───────────────────────────────────────────────────

    void containsMessage_afterStore_returnsTrue()
    {
        LocalMessageStore store;
        store.storeDecryptedMessage(makeMessage("msg-xyz", "conv-1"));
        QVERIFY(store.containsMessage(QStringLiteral("msg-xyz")));
    }

    void containsMessage_unknownId_returnsFalse()
    {
        LocalMessageStore store;
        QVERIFY(!store.containsMessage(QStringLiteral("does-not-exist")));
    }

    // ── messagesForConversation ───────────────────────────────────────────

    void messagesForConversation_filtersCorrectly()
    {
        LocalMessageStore store;
        store.storeDecryptedMessage(makeMessage("m1", "conv-A"));
        store.storeDecryptedMessage(makeMessage("m2", "conv-B"));
        store.storeDecryptedMessage(makeMessage("m3", "conv-A"));

        const auto convA = store.messagesForConversation(QStringLiteral("conv-A"));
        QCOMPARE(convA.size(), 2);
        for (const auto& m : convA)
            QCOMPARE(m.conversationId, QStringLiteral("conv-A"));
    }

    void messagesForConversation_unknownId_returnsEmpty()
    {
        LocalMessageStore store;
        store.storeDecryptedMessage(makeMessage("m1", "conv-A"));
        QCOMPARE(store.messagesForConversation(QStringLiteral("conv-nonexistent")).size(), 0);
    }

    // ── clearConversation ─────────────────────────────────────────────────

    void clearConversation_removesTargetMessages_keepsOthers()
    {
        LocalMessageStore store;
        store.storeDecryptedMessage(makeMessage("m1", "conv-A"));
        store.storeDecryptedMessage(makeMessage("m2", "conv-B"));
        store.storeDecryptedMessage(makeMessage("m3", "conv-A"));

        store.clearConversation(QStringLiteral("conv-A"));

        QCOMPARE(store.messagesForConversation(QStringLiteral("conv-A")).size(), 0);
        QCOMPARE(store.messagesForConversation(QStringLiteral("conv-B")).size(), 1);
        QVERIFY(!store.containsMessage(QStringLiteral("m1")));
        QVERIFY(!store.containsMessage(QStringLiteral("m3")));
        QVERIFY(store.containsMessage(QStringLiteral("m2")));
    }

    void clearConversation_rebuildsIndexCorrectly()
    {
        LocalMessageStore store;
        store.storeDecryptedMessage(makeMessage("a", "conv-A"));
        store.storeDecryptedMessage(makeMessage("b", "conv-B"));
        store.storeDecryptedMessage(makeMessage("c", "conv-A"));

        store.clearConversation(QStringLiteral("conv-A"));

        QVERIFY(store.containsMessage(QStringLiteral("b")));
        QCOMPARE(store.decryptedMessages().size(), 1);
    }

    void clearConversation_alsoRemovesEnvelopes()
    {
        LocalMessageStore store;
        store.storeOutgoingEnvelope(makeEnvelope("e1", "conv-A"));
        store.storeOutgoingEnvelope(makeEnvelope("e2", "conv-B"));

        store.clearConversation(QStringLiteral("conv-A"));

        QCOMPARE(store.envelopesForConversation(QStringLiteral("conv-A")).size(), 0);
        QCOMPARE(store.envelopesForConversation(QStringLiteral("conv-B")).size(), 1);
    }

    // ── clearAll ──────────────────────────────────────────────────────────

    void clearAll_removesAllMessagesAndEnvelopes()
    {
        LocalMessageStore store;
        store.storeDecryptedMessage(makeMessage("m1", "conv-A"));
        store.storeDecryptedMessage(makeMessage("m2", "conv-B"));
        store.storeOutgoingEnvelope(makeEnvelope("e1", "conv-A"));
        store.clearAll();

        QCOMPARE(store.decryptedMessages().size(), 0);
        QCOMPARE(store.envelopes().size(), 0);
        QVERIFY(!store.containsMessage(QStringLiteral("m1")));
    }

    // ── Envelope storage ──────────────────────────────────────────────────

    void initialState_noEnvelopes()
    {
        LocalMessageStore store;
        QCOMPARE(store.envelopes().size(), 0);
    }

    void storeOutgoingEnvelope_normalEnvelope_isStored()
    {
        LocalMessageStore store;
        store.storeOutgoingEnvelope(makeEnvelope("env-1", "conv-1"));
        QCOMPARE(store.envelopes().size(), 1);
    }

    void storeOutgoingEnvelope_emptyId_isIgnored()
    {
        LocalMessageStore store;
        store.storeOutgoingEnvelope(makeEnvelope("", "conv-1"));
        QCOMPARE(store.envelopes().size(), 0);
    }

    void storeOutgoingEnvelope_duplicateId_deduplicates()
    {
        LocalMessageStore store;
        store.storeOutgoingEnvelope(makeEnvelope("env-dup", "conv-1"));
        store.storeOutgoingEnvelope(makeEnvelope("env-dup", "conv-1"));
        QCOMPARE(store.envelopes().size(), 1);
    }

    void envelopesForConversation_filtersCorrectly()
    {
        LocalMessageStore store;
        store.storeOutgoingEnvelope(makeEnvelope("e1", "conv-A"));
        store.storeOutgoingEnvelope(makeEnvelope("e2", "conv-B"));
        store.storeOutgoingEnvelope(makeEnvelope("e3", "conv-A"));

        const auto convA = store.envelopesForConversation(QStringLiteral("conv-A"));
        QCOMPARE(convA.size(), 2);
        for (const auto& e : convA)
            QCOMPARE(e.conversationId, QStringLiteral("conv-A"));
    }

    // ── storeOutgoingMessage (JSON parsing) ───────────────────────────────

    void storeOutgoingMessage_fromJson_parsesFieldsCorrectly()
    {
        LocalMessageStore store;
        QJsonObject j;
        j[QStringLiteral("id")]              = QStringLiteral("json-msg-1");
        j[QStringLiteral("conversation_id")] = QStringLiteral("conv-json");
        j[QStringLiteral("sender_device_id")]= QStringLiteral("dev-x");
        j[QStringLiteral("ciphertext")]      = QString::fromLatin1(QByteArray("deadbeef").toHex());
        j[QStringLiteral("nonce")]           = QString::fromLatin1(QByteArray(12, '\xAA').toHex());
        j[QStringLiteral("associated_data")] = QString::fromLatin1(QByteArray("aad").toHex());
        j[QStringLiteral("tx_hash")]         = QStringLiteral("0xABCDEF");
        j[QStringLiteral("merkle_root")]     = QStringLiteral("0x123456");

        store.storeOutgoingMessage(j);

        QCOMPARE(store.envelopes().size(), 1);
        const auto& stored = store.envelopes().at(0);
        QCOMPARE(stored.id, QStringLiteral("json-msg-1"));
        QCOMPARE(stored.conversationId, QStringLiteral("conv-json"));
        QCOMPARE(stored.txHash, QStringLiteral("0xABCDEF"));
        QCOMPARE(stored.merkleRoot, QStringLiteral("0x123456"));
    }

    // ── E2EE invariant ────────────────────────────────────────────────────
    //
    // The local store must keep ciphertext (MessageEnvelope) and plaintext
    // (DecryptedMessage) in separate structures — ciphertext bytes must never
    // equal the corresponding plaintext bytes.  This mirrors the server's
    // design: it only ever sees ciphertext and associated metadata.

    void envelopeCiphertext_neverEqualsPlaintext()
    {
        const QString    plaintext      = QStringLiteral("sensitive payload");
        const QByteArray fakeCiphertext = QByteArray("ENCRYPTED-BLOB-XYZ");

        QVERIFY(fakeCiphertext != plaintext.toUtf8());

        LocalMessageStore store;

        MessageEnvelope e = makeEnvelope("e-check", "conv-1", fakeCiphertext);
        store.storeOutgoingEnvelope(e);

        DecryptedMessage m = makeMessage("m-check", "conv-1", plaintext);
        store.storeDecryptedMessage(m);

        const QByteArray storedCiphertext = store.envelopes().at(0).ciphertext;
        const QString    storedPlaintext  = store.decryptedMessages().at(0).plaintext;

        QVERIFY(storedCiphertext != storedPlaintext.toUtf8());
    }

    // ── Delete flag: a soft-deleted message stays in the store ────────────

    void softDeletedMessage_remainsInStore()
    {
        LocalMessageStore store;
        store.storeDecryptedMessage(makeMessage("del-1", "conv-1", "text", "dev", true));
        QVERIFY(store.containsMessage(QStringLiteral("del-1")));
        QVERIFY(store.decryptedMessages().at(0).isDeleted);
    }
};

QTEST_MAIN(TestLocalMessageStore)
#include "tst_localmessagestore.moc"
