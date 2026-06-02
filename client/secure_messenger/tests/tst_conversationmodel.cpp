// Unit tests for ConversationModel.
//
// Coverage:
//   - rowCount lifecycle (empty → setConversations → replace)
//   - All QML data roles: ConversationId, Participant, LastMessage,
//     Fingerprint, UpdatedAt, UnreadCount, Verified
//   - fingerprintForConversation: known id, unknown id
//   - setFingerprintForConversation: update fingerprint + verified flag,
//     unknown id returns false, emits dataChanged
//   - Invalid index returns empty QVariant
//   - setConversations replaces previous data
//
// Brief alignment (C++ — Memon):
//   Demonstrates QAbstractListModel subclassing, model roles, and
//   controlled data mutation (setFingerprintForConversation emits
//   dataChanged for precise QML re-binding).
//
// Brief alignment (Cryptography — O'Brien / Networks — Burkley):
//   The fingerprint and verified roles feed the TOFU UI — tests verify
//   that the model can represent pinned/changed fingerprints accurately,
//   which is required for detecting MITM / key-compromise scenarios.

#include <QtTest>
#include <QSignalSpy>

#include "../src/models/ConversationModel.h"

// ── Helper ────────────────────────────────────────────────────────────────────

static ConversationItem makeItem(
    const QString& id,
    const QString& participant,
    const QString& lastMsg      = QString{},
    const QString& fingerprint  = QString{},
    int            unread       = 0,
    bool           verified     = false)
{
    ConversationItem item;
    item.conversationId = id;
    item.participant    = participant;
    item.deviceId       = QStringLiteral("device-001");
    item.lastMessage    = lastMsg;
    item.fingerprint    = fingerprint;
    item.unreadCount    = unread;
    item.verified       = verified;
    item.updatedAt      = QDateTime::fromMSecsSinceEpoch(2000000LL);
    return item;
}

// ── Test class ────────────────────────────────────────────────────────────────

class TestConversationModel : public QObject
{
    Q_OBJECT

private slots:
    void initialState_rowCountIsZero()
    {
        ConversationModel model;
        QCOMPARE(model.rowCount(), 0);
    }

    void setConversations_updatesRowCount()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice"), makeItem("c2", "bob")});
        QCOMPARE(model.rowCount(), 2);
    }

    void setConversations_replacesExistingItems()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice")});
        model.setConversations({makeItem("c2", "bob"), makeItem("c3", "carol")});
        QCOMPARE(model.rowCount(), 2);
        QCOMPARE(
            model.data(model.index(0), ConversationModel::ParticipantRole).toString(),
            QStringLiteral("bob"));
    }

    void setConversations_emitsModelReset()
    {
        ConversationModel model;
        QSignalSpy spy(&model, &QAbstractItemModel::modelReset);
        model.setConversations({makeItem("c1", "alice")});
        QCOMPARE(spy.count(), 1);
    }

    // ── Data roles ────────────────────────────────────────────────────────

    void data_conversationIdRole_returnsId()
    {
        ConversationModel model;
        model.setConversations({makeItem("conv-xyz", "alice")});
        QCOMPARE(
            model.data(model.index(0), ConversationModel::ConversationIdRole).toString(),
            QStringLiteral("conv-xyz"));
    }

    void data_participantRole_returnsParticipant()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice_user")});
        QCOMPARE(
            model.data(model.index(0), ConversationModel::ParticipantRole).toString(),
            QStringLiteral("alice_user"));
    }

    void data_lastMessageRole_returnsLastMessage()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice", "Last message preview")});
        QCOMPARE(
            model.data(model.index(0), ConversationModel::LastMessageRole).toString(),
            QStringLiteral("Last message preview"));
    }

    void data_fingerprintRole_returnsFingerprint()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice", QString{}, "fp-deadbeef")});
        QCOMPARE(
            model.data(model.index(0), ConversationModel::FingerprintRole).toString(),
            QStringLiteral("fp-deadbeef"));
    }

    void data_unreadCountRole_returnsCount()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice", QString{}, QString{}, 7)});
        QCOMPARE(
            model.data(model.index(0), ConversationModel::UnreadCountRole).toInt(), 7);
    }

    void data_verifiedRole_trueWhenVerified()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice", QString{}, QString{}, 0, true)});
        QVERIFY(model.data(model.index(0), ConversationModel::VerifiedRole).toBool());
    }

    void data_verifiedRole_falseByDefault()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice")});
        QVERIFY(!model.data(model.index(0), ConversationModel::VerifiedRole).toBool());
    }

    void data_updatedAtRole_returnsValidDateTime()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice")});
        QVERIFY(
            model.data(model.index(0), ConversationModel::UpdatedAtRole)
                .toDateTime().isValid());
    }

    // ── Invalid index / unknown role ──────────────────────────────────────

    void data_negativeIndex_returnsInvalidVariant()
    {
        ConversationModel model;
        QVERIFY(
            !model.data(model.index(-1), ConversationModel::ConversationIdRole).isValid());
    }

    void data_outOfBoundsIndex_returnsInvalidVariant()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice")});
        QVERIFY(
            !model.data(model.index(100), ConversationModel::ConversationIdRole).isValid());
    }

    // ── fingerprintForConversation ────────────────────────────────────────

    void fingerprintForConversation_knownId_returnsFingerprint()
    {
        ConversationModel model;
        model.setConversations({makeItem("conv-fp", "alice", QString{}, "fp-abc123")});
        QCOMPARE(
            model.fingerprintForConversation(QStringLiteral("conv-fp")),
            QStringLiteral("fp-abc123"));
    }

    void fingerprintForConversation_unknownId_returnsEmptyString()
    {
        ConversationModel model;
        model.setConversations({makeItem("conv-fp", "alice")});
        QVERIFY(model.fingerprintForConversation(QStringLiteral("nonexistent")).isEmpty());
    }

    void fingerprintForConversation_emptyModel_returnsEmptyString()
    {
        ConversationModel model;
        QVERIFY(model.fingerprintForConversation(QStringLiteral("any-id")).isEmpty());
    }

    // ── setFingerprintForConversation ─────────────────────────────────────

    void setFingerprintForConversation_knownId_updatesFingerprint()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice", QString{}, "old-fp", 0, false)});
        const bool ok = model.setFingerprintForConversation("c1", "new-fp", true);
        QVERIFY(ok);
        QCOMPARE(model.fingerprintForConversation(QStringLiteral("c1")),
                 QStringLiteral("new-fp"));
    }

    void setFingerprintForConversation_knownId_updatesVerifiedFlag()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice", QString{}, "fp", 0, false)});
        model.setFingerprintForConversation("c1", "fp", true);
        QVERIFY(model.data(model.index(0), ConversationModel::VerifiedRole).toBool());
    }

    void setFingerprintForConversation_canUnverify()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice", QString{}, "fp", 0, true)});
        model.setFingerprintForConversation("c1", "fp", false);
        QVERIFY(!model.data(model.index(0), ConversationModel::VerifiedRole).toBool());
    }

    void setFingerprintForConversation_unknownId_returnsFalse()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice")});
        QVERIFY(!model.setFingerprintForConversation("nonexistent", "fp", true));
    }

    void setFingerprintForConversation_emitsDataChanged()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice", QString{}, "old-fp")});
        QSignalSpy spy(&model, &QAbstractItemModel::dataChanged);
        model.setFingerprintForConversation("c1", "new-fp", true);
        QCOMPARE(spy.count(), 1);
    }

    void setFingerprintForConversation_emitsDataChanged_withCorrectRoles()
    {
        ConversationModel model;
        model.setConversations({makeItem("c1", "alice", QString{}, "fp")});
        QSignalSpy spy(&model, &QAbstractItemModel::dataChanged);
        model.setFingerprintForConversation("c1", "new-fp", true);

        QCOMPARE(spy.count(), 1);
        const QList<int> roles = spy.at(0).at(2).value<QVector<int>>().toList();
        QVERIFY(roles.contains(ConversationModel::FingerprintRole));
        QVERIFY(roles.contains(ConversationModel::VerifiedRole));
    }
};

QTEST_MAIN(TestConversationModel)
#include "tst_conversationmodel.moc"
