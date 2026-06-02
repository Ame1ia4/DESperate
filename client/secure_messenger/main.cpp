
#include <QFile>
#include <QGuiApplication>
#include <QDebug>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>

#include "src/controllers/AuthController.h"
#include "src/controllers/ConversationController.h"
#include "src/controllers/MessageController.h"

#include "src/storage/SessionStore.h"
#include "src/storage/TrustStore.h"

#include "src/services/ApiClient.h"
#include "src/services/CryptoServiceClient.h"

#include "src/storage/LocalMessageStore.h"
#include "src/utils/ClipboardHelper.h"

    int main(
        int argc,
        char* argv[])
{
    QGuiApplication app(argc, argv);

    app.setOrganizationName("DESperate");
    app.setApplicationName("secure_messenger");

    // Must be set before the QML engine is created.
    // Basic style supports background/contentItem customization.
    QQuickStyle::setStyle("Basic");

    QQmlApplicationEngine engine;

    // Core services — cryptoClient must be declared before apiClient
    // so apiClient can hold a pointer to it.
    CryptoServiceClient cryptoClient;

    ApiClient apiClient(&cryptoClient);

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

    // When a conversation is opened, fetch its server-side history and decrypt.
    QObject::connect(
        &conversationController,
        &ConversationController::conversationOpened,
        &messageController,
        &MessageController::fetchConversationHistory,
        Qt::QueuedConnection);

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

    // Clipboard helper for QML (avoid depending on Qt.labs.platform)
    ClipboardHelper clipboardHelper;
    engine.rootContext()->setContextProperty("clipboardHelper", &clipboardHelper);

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
