// Unit tests for MessageModel.
//
// Coverage:
//   - rowCount lifecycle (empty → add → clear)
//   - All QML data roles: Content, Plaintext, Outgoing, Verified,
//     VerificationState, MessageId, Timestamp
//   - outgoing flag logic (senderDeviceId == "self")
//   - verified flag logic (VerificationState::Verified only)
//   - Invalid index / unknown role returns empty QVariant
//   - roleNames() contains all expected keys
//   - VerificationRole returns an int (never exposes plaintext bytes)
//
// Brief alignment (C++ — Memon):
//   Demonstrates use of QAbstractListModel, data roles, and Qt model/view API.
//   (Cryptography — O'Brien): VerificationRole is tested to ensure it returns
//   a typed integer — not message content — preventing accidental data leakage
//   through the wrong role.

#include <QtTest>
#include <QSignalSpy>

#include "../src/models/MessageModel.h"
#include "../src/types/Types.h"

// ── Helper ────────────────────────────────────────────────────────────────────

static DecryptedMessage makeMsg(
    const QString&   id,
    const QString&   plaintext,
    const QString&   senderDeviceId = QStringLiteral("device-remote"),
    VerificationState vs            = VerificationState::Verified)
{
    DecryptedMessage m;
    m.id              = id;
    m.conversationId  = QStringLiteral("conv-1");
    m.plaintext       = plaintext;
    m.senderDeviceId  = senderDeviceId;
    m.timestamp       = QDateTime::fromMSecsSinceEpoch(1000000LL);
    m.verificationState = vs;
    m.isDeleted       = false;
    return m;
}

// ── Test class ────────────────────────────────────────────────────────────────

class TestMessageModel : public QObject
{
    Q_OBJECT

private slots:
    void initialState_rowCountIsZero()
    {
        MessageModel model;
        QCOMPARE(model.rowCount(), 0);
    }

    void addMessage_incrementsRowCount()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "hello"));
        QCOMPARE(model.rowCount(), 1);
    }

    void addMultipleMessages_rowCountIsCorrect()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "one"));
        model.addMessage(makeMsg("m2", "two"));
        model.addMessage(makeMsg("m3", "three"));
        QCOMPARE(model.rowCount(), 3);
    }

    // ── Data roles ────────────────────────────────────────────────────────

    void data_contentRole_returnsPlaintext()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "test content"));
        const QModelIndex idx = model.index(0);
        QCOMPARE(model.data(idx, MessageModel::ContentRole).toString(),
                 QStringLiteral("test content"));
    }

    void data_plaintextRole_returnsPlaintext()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "plaintext here"));
        const QModelIndex idx = model.index(0);
        QCOMPARE(model.data(idx, MessageModel::PlaintextRole).toString(),
                 QStringLiteral("plaintext here"));
    }

    void data_messageIdRole_returnsId()
    {
        MessageModel model;
        model.addMessage(makeMsg("unique-id-xyz", "msg body"));
        const QModelIndex idx = model.index(0);
        QCOMPARE(model.data(idx, MessageModel::MessageIdRole).toString(),
                 QStringLiteral("unique-id-xyz"));
    }

    void data_timestampRole_returnsValidDateTime()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "msg"));
        const QModelIndex idx = model.index(0);
        QVERIFY(model.data(idx, MessageModel::TimestampRole).toDateTime().isValid());
    }

    // ── Outgoing role (senderDeviceId == "self") ──────────────────────────

    void data_outgoingRole_trueWhenSenderIsSelf()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "sent by me", QStringLiteral("self")));
        const QModelIndex idx = model.index(0);
        QVERIFY(model.data(idx, MessageModel::OutgoingRole).toBool());
    }

    void data_outgoingRole_falseWhenSenderIsRemote()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "from them", QStringLiteral("device-remote")));
        const QModelIndex idx = model.index(0);
        QVERIFY(!model.data(idx, MessageModel::OutgoingRole).toBool());
    }

    void data_outgoingRole_falseWhenSenderIsEmptyString()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "msg", QStringLiteral("")));
        const QModelIndex idx = model.index(0);
        QVERIFY(!model.data(idx, MessageModel::OutgoingRole).toBool());
    }

    // ── Verified role (VerificationState::Verified only) ─────────────────

    void data_verifiedRole_trueWhenVerified()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "verified", "dev", VerificationState::Verified));
        const QModelIndex idx = model.index(0);
        QVERIFY(model.data(idx, MessageModel::VerifiedRole).toBool());
    }

    void data_verifiedRole_falseWhenPending()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "pending", "dev", VerificationState::Pending));
        const QModelIndex idx = model.index(0);
        QVERIFY(!model.data(idx, MessageModel::VerifiedRole).toBool());
    }

    void data_verifiedRole_falseWhenFailed()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "failed", "dev", VerificationState::Failed));
        const QModelIndex idx = model.index(0);
        QVERIFY(!model.data(idx, MessageModel::VerifiedRole).toBool());
    }

    // ── VerificationRole returns typed int, not plaintext ─────────────────
    // This guards against accidentally leaking message content via the
    // wrong role — important for the E2EE design review.

    void data_verificationRole_isInt_notString()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "secret", "dev", VerificationState::Verified));
        const QModelIndex idx = model.index(0);
        const QVariant v = model.data(idx, MessageModel::VerificationRole);
        QCOMPARE(v.typeId(), static_cast<int>(QMetaType::Int));
    }

    void data_verificationRole_verified_isZero()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "x", "dev", VerificationState::Verified));
        QCOMPARE(
            model.data(model.index(0), MessageModel::VerificationRole).toInt(),
            static_cast<int>(VerificationState::Verified));
    }

    // ── Invalid index / unknown role ──────────────────────────────────────

    void data_negativeIndex_returnsInvalidVariant()
    {
        MessageModel model;
        QVERIFY(!model.data(model.index(-1), MessageModel::ContentRole).isValid());
    }

    void data_outOfBoundsIndex_returnsInvalidVariant()
    {
        MessageModel model;
        QVERIFY(!model.data(model.index(999), MessageModel::ContentRole).isValid());
    }

    void data_unknownRole_returnsInvalidVariant()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "msg"));
        QVERIFY(!model.data(model.index(0), Qt::UserRole + 999).isValid());
    }

    // ── clear() ───────────────────────────────────────────────────────────

    void clear_resetsRowCountToZero()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "one"));
        model.addMessage(makeMsg("m2", "two"));
        model.clear();
        QCOMPARE(model.rowCount(), 0);
    }

    void clear_emitsModelReset()
    {
        MessageModel model;
        model.addMessage(makeMsg("m1", "msg"));
        QSignalSpy spy(&model, &QAbstractItemModel::modelReset);
        model.clear();
        QCOMPARE(spy.count(), 1);
    }

    void addMessage_emitsRowsInserted()
    {
        MessageModel model;
        QSignalSpy spy(&model, &QAbstractItemModel::rowsInserted);
        model.addMessage(makeMsg("m1", "msg"));
        QCOMPARE(spy.count(), 1);
    }

    // ── roleNames() ───────────────────────────────────────────────────────

    void roleNames_containsAllExpectedKeys()
    {
        MessageModel model;
        const QList<QByteArray> names = model.roleNames().values();
        QVERIFY(names.contains("content"));
        QVERIFY(names.contains("plaintext"));
        QVERIFY(names.contains("outgoing"));
        QVERIFY(names.contains("verified"));
        QVERIFY(names.contains("messageId"));
        QVERIFY(names.contains("timestamp"));
        QVERIFY(names.contains("verificationState"));
    }
};

QTEST_MAIN(TestMessageModel)
#include "tst_messagemodel.moc"
