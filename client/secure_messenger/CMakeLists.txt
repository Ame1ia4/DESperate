cmake_minimum_required(VERSION 3.16)

project(secure_messenger VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Quick)

qt_standard_project_setup(REQUIRES 6.10)

qt_add_executable(appsecure_messenger


    src/services/ApiClient.cpp
    src/services/CryptoServiceClient.cpp

    src/models/MessageModel.cpp
)

qt_add_qml_module(appsecure_messenger
    URI secure_messenger
    QML_FILES

        SOURCES src/types/Types.h
        SOURCES src/services/ApiClient.h
        SOURCES src/services/ApiClient.cpp
        SOURCES src/services/CryptoServiceClient.h src/services/CryptoServiceClient.cpp
        SOURCES src/models/MessageModel.h src/models/MessageModel.cpp
        QML_FILES qml/views/MessageView.qml
        QML_FILES qml/views/LoginView.qml
        SOURCES src/controllers/AuthController.h src/controllers/AuthController.cpp
        SOURCES src/controllers/MessageController.h src/controllers/MessageController.cpp
        SOURCES
        SOURCES
        SOURCES src/models/ConversationModel.h src/models/ConversationModel.cpp
        SOURCES
        SOURCES src/services/BlockchainVerifier.h src/services/BlockchainVerifier.cpp
        SOURCES
        SOURCES
        SOURCES src/network/TLSManager.h src/network/TLSManager.cpp
        SOURCES src/storage/LocalMessageStore.h src/storage/LocalMessageStore.cpp
        SOURCES
        QML_FILES qml/views/ConversationList.qml
        QML_FILES qml/views/MessageDelegate.qml
        QML_FILES qml/views/VerifyDialog.qml
        QML_FILES qml/views/SettingsView.qml
        QML_FILES qml/views/UserSearchSheet.qml
        QML_FILES
        RESOURCES src/crypto/crypto_service.py
        RESOURCES src/crypto/key_store.py
        RESOURCES src/crypto/requirements.txt
        RESOURCES
        QML_FILES qml/main.qml
        RESOURCES qml/qmldir
        SOURCES main.cpp
)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
set_target_properties(appsecure_messenger PROPERTIES
#    MACOSX_BUNDLE_GUI_IDENTIFIER com.example.appsecure_messenger
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

target_link_libraries(appsecure_messenger
    PRIVATE Qt6::Quick
)

install(TARGETS appsecure_messenger
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
