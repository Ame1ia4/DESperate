#include <QtTest>
#include <QSignalSpy>
#include <QGuiApplication>
#include <QClipboard>
#include <QJsonObject>

#include "src/controllers/MessageController.h"
#include "src/services/ApiClient.h"
#include "src/services/CryptoServiceClient.h"

class MockApiClient : public ApiClient
{
    Q_OBJECT
public:
    explicit MockApiClient() : ApiClient(nullptr) {}

    void fetchMessageBlockchainVerify(const QString& id) override
    {
        m_lastRequestedId = id;
    }

    void triggerSuccess(const QString& id, const QJsonObject& data)
    {
        emit blockchainVerifySucceeded(id, data);
    }

    void triggerFailure(const QString& id, const QString& reason)
    {
        emit blockchainVerifyFailed(id, reason);
    }

    QString m_lastRequestedId;
};

class TestCopyMerkleRoot : public QObject
{
    Q_OBJECT

private slots:
    void copiesRootToClipboard_whenConfirmed()
    {
        MockApiClient api;
        CryptoServiceClient crypto;
        MessageController ctrl(&api, &crypto, nullptr, nullptr, nullptr, nullptr, nullptr);
        QSignalSpy spy(&ctrl, &MessageController::merkleRootCopied);

        ctrl.copyMerkleRoot("msg-1");
        QCOMPARE(api.m_lastRequestedId, QString("msg-1"));

        QJsonObject data;
        data["status"]      = "stored-on-blockchain";
        data["merkle_root"] = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        api.triggerSuccess("msg-1", data);

        QCOMPARE(spy.count(), 1);
        QCOMPARE(spy.at(0).at(0).toString(), data["merkle_root"].toString());
        QCOMPARE(QGuiApplication::clipboard()->text(), data["merkle_root"].toString());
    }

    void emitsPending_whenStatusIsPending()
    {
        MockApiClient api;
        CryptoServiceClient crypto;
        MessageController ctrl(&api, &crypto, nullptr, nullptr, nullptr, nullptr, nullptr);
        QSignalSpy spy(&ctrl, &MessageController::merkleRootPending);

        ctrl.copyMerkleRoot("msg-2");

        QJsonObject data;
        data["status"] = "pending";
        api.triggerSuccess("msg-2", data);

        QCOMPARE(spy.count(), 1);
    }

    void emitsPending_whenStatusIsNothing()
    {
        MockApiClient api;
        CryptoServiceClient crypto;
        MessageController ctrl(&api, &crypto, nullptr, nullptr, nullptr, nullptr, nullptr);
        QSignalSpy spy(&ctrl, &MessageController::merkleRootPending);

        ctrl.copyMerkleRoot("msg-3");

        QJsonObject data;
        data["status"] = "nothing";
        api.triggerSuccess("msg-3", data);

        QCOMPARE(spy.count(), 1);
    }

    void emitsPending_onApiFailure()
    {
        MockApiClient api;
        CryptoServiceClient crypto;
        MessageController ctrl(&api, &crypto, nullptr, nullptr, nullptr, nullptr, nullptr);
        QSignalSpy spy(&ctrl, &MessageController::merkleRootPending);

        ctrl.copyMerkleRoot("msg-4");
        api.triggerFailure("msg-4", "network error");

        QCOMPARE(spy.count(), 1);
    }

    void ignoresResponsesForDifferentMessageId()
    {
        MockApiClient api;
        CryptoServiceClient crypto;
        MessageController ctrl(&api, &crypto, nullptr, nullptr, nullptr, nullptr, nullptr);
        QSignalSpy copiedSpy(&ctrl, &MessageController::merkleRootCopied);
        QSignalSpy pendingSpy(&ctrl, &MessageController::merkleRootPending);

        ctrl.copyMerkleRoot("msg-5");

        QJsonObject data;
        data["status"]      = "stored-on-blockchain";
        data["merkle_root"] = "0xabc";
        api.triggerSuccess("msg-OTHER", data);  // wrong id — must be ignored

        QCOMPARE(copiedSpy.count(), 0);
        QCOMPARE(pendingSpy.count(), 0);
    }
};

QTEST_MAIN(TestCopyMerkleRoot)
#include "tst_copymerkleroot.moc"
