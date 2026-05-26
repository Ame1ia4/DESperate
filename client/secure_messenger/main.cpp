#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>

#include "controllers/AuthController.h"
#include "controllers/MessageController.h"
#include "services/ApiClient.h"
#include "services/CryptoServiceClient.h"
#include "services/LocalMessageStore.h"
#include "services/TrustStore.h"
#include "services/MessageSyncService.h"
#include "models/MessageModel.h"

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);

    ApiClient apiClient;
    CryptoServiceClient crypto;
    LocalMessageStore localStore;
    TrustStore trustStore;
    MessageModel messageModel;

    AuthController authController(
        &apiClient,
        &crypto,
        &trustStore
        );

    MessageController messageController(
        &apiClient,
        &crypto,
        &localStore,
        &messageModel,
        &trustStore
        );

    MessageSyncService syncService(
        &apiClient,
        &crypto,
        &localStore,
        &messageModel
        );

    QQmlApplicationEngine engine;

    engine.rootContext()->setContextProperty(
        "authController",
        &authController
        );

    engine.rootContext()->setContextProperty(
        "messageController",
        &messageController
        );

    engine.rootContext()->setContextProperty(
        "messageModel",
        &messageModel
        );

    engine.load(QUrl("qrc:/qml/Main.qml"));

    return app.exec();
}