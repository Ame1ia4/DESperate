
#include <QFile>
#include <QGuiApplication>
#include <QDebug>
#include <QQmlApplicationEngine>
#include <QQmlContext>

#include "src/controllers/AuthController.h"
#include "src/controllers/ConversationController.h"
#include "src/controllers/MessageController.h"

#include "src/storage/SessionStore.h"
#include "src/storage/TrustStore.h"

#include "src/services/ApiClient.h"
#include "src/services/CryptoServiceClient.h"

#include "src/storage/LocalMessageStore.h"

    int main(
        int argc,
        char* argv[])
{
    QGuiApplication app(argc, argv);

    app.setOrganizationName("DESperate");
    app.setApplicationName("secure_messenger");

    QQmlApplicationEngine engine;

    // Core services
    ApiClient apiClient;

    CryptoServiceClient cryptoClient;

    // Persistent local stores
    TrustStore trustStore;

    SessionStore sessionStore;

    LocalMessageStore localMessageStore;

    // Controllers
    ConversationController
        conversationController(
            &apiClient,
            &cryptoClient,
            &localMessageStore,
            &trustStore);

    AuthController authController(
        &apiClient,
        &cryptoClient,
        &trustStore,
        &sessionStore);

    MessageController
        messageController(
            &apiClient,
            &cryptoClient,
            &localMessageStore,
            conversationController.messages(),
            &conversationController,
            &trustStore,
            &sessionStore);

    // QML context exposure
    engine.rootContext()->setContextProperty(
        "conversationController",
        &conversationController);

    engine.rootContext()->setContextProperty(
        "authController",
        &authController);

    engine.rootContext()->setContextProperty(
        "messageController",
        &messageController);

    // Load QML module
    engine.loadFromModule(
        "secure_messenger",
        "Main");

    // Fallback resource loading
    if (engine.rootObjects().isEmpty()) {

        const QUrl fallbackUrl(
            QStringLiteral(
                "qrc:/qml/Main.qml"));

        if (QFile::exists(
                ":/qml/Main.qml")) {

            qWarning()
            << "Module load failed,"
            << "falling back to"
            << fallbackUrl;

            engine.load(
                fallbackUrl);

        } else {

            qWarning()
            << "QML entrypoint missing"
            << "in resources."
            << "Expected"
            << ":/qml/Main.qml";
        }
    }

    if (engine.rootObjects().isEmpty()) {
        return -1;
    }

    return app.exec();
}
