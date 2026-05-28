#include <QGuiApplication>
#include <QFile>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QDebug>

#include "src/controllers/AuthController.h"
#include "src/controllers/ConversationController.h"
#include "src/services/ApiClient.h"
#include "src/services/CryptoServiceClient.h"

int main(int argc, char* argv[])
{
    QGuiApplication app(argc, argv);

    QQmlApplicationEngine engine;

    ApiClient apiClient;
    CryptoServiceClient cryptoClient;

    ConversationController conversationController(
        &apiClient,
        &cryptoClient);
    AuthController authController(
        &apiClient,
        &cryptoClient);

    engine.rootContext()->setContextProperty(
        "conversationController",
        &conversationController);
    engine.rootContext()->setContextProperty(
        "authController",
        &authController);

    engine.loadFromModule("secure_messenger", "Main");
    if (engine.rootObjects().isEmpty()) {
        const QUrl fallbackUrl(QStringLiteral("qrc:/qml/Main.qml"));
        if (QFile::exists(":/qml/Main.qml")) {
            qWarning() << "Module load failed, falling back to" << fallbackUrl;
            engine.load(fallbackUrl);
        } else {
            qWarning() << "QML entrypoint missing in resources. Expected :/qml/Main.qml";
        }
    }

    if (engine.rootObjects().isEmpty()) {
        return -1;
    }

    return app.exec();
}