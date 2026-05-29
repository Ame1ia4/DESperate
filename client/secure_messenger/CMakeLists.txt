cmake_minimum_required(VERSION 3.16)

project(secure_messenger VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD_REQUIRED ON)

<<<<<<< Updated upstream
find_package(Qt6 REQUIRED COMPONENTS Quick Network QuickControls2)
=======
find_package(Qt6 REQUIRED COMPONENTS Quick Network)
find_package(OpenSSL REQUIRED)
>>>>>>> Stashed changes

qt_standard_project_setup(REQUIRES 6.10)

qt_add_executable(appsecure_messenger
    main.cpp
    resources.qrc
    src/services/ApiClient.cpp
    src/services/CryptoServiceClient.cpp
    src/controllers/AuthController.cpp
    src/controllers/MessageController.cpp
    src/controllers/ConversationController.cpp
    src/models/MessageModel.cpp
    src/models/ConversationModel.cpp
    src/models/UserModel.cpp
    src/network/TLSManager.cpp
    src/storage/LocalMessageStore.cpp
)

qt_add_qml_module(appsecure_messenger
    URI secure_messenger
    QML_FILES
        qml/Main.qml
        qml/main.qml
        qml/views/ConversationList.qml
        qml/views/LoginView.qml
        qml/views/SignupView.qml
        qml/views/MessageDelegate.qml
        qml/views/MessageView.qml
        qml/views/SettingsView.qml
        qml/views/UserSearchSheet.qml
        qml/views/VerifyDialog.qml

<<<<<<< Updated upstream
    SOURCES
        src/types/Types.h
        src/services/ApiClient.h
        src/services/CryptoServiceClient.h
        src/controllers/AuthController.h
        src/controllers/MessageController.h
        src/controllers/ConversationController.h
        src/models/MessageModel.h
        src/models/ConversationModel.h
        src/models/UserModel.h
        src/network/TLSManager.h
        src/storage/LocalMessageStore.h
        SOURCES src/models/DeviceModel.h src/models/DeviceModel.cpp
        SOURCES src/models/SessionModel.h src/models/SessionModel.cpp
        SOURCES src/storage/TrustStore.h src/storage/TrustStore.cpp
        SOURCES src/storage/SessionStore.h src/storage/SessionStore.cpp
=======
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
        SOURCES
        SOURCES
        SOURCES
        SOURCES src/network/TLSManager.h src/network/TLSManager.cpp
        SOURCES src/network/TrustStore.h src/network/TrustStore.cpp
        SOURCES src/storage/LocalMessageStore.h src/storage/LocalMessageStore.cpp
        SOURCES
        QML_FILES qml/views/ConversationList.qml
        QML_FILES qml/views/MessageDelegate.qml
        QML_FILES qml/views/VerifyDialog.qml
        QML_FILES qml/views/SettingsView.qml
        QML_FILES qml/views/UserSearchSheet.qml
        QML_FILES
        RESOURCES
        RESOURCES
        RESOURCES
        RESOURCES
        QML_FILES qml/main.qml
        RESOURCES qml/qmldir
        SOURCES main.cpp
        SOURCES src/controllers/ConversationController.h src/controllers/ConversationController.cpp
        SOURCES src/models/UserModel.h src/models/UserModel.cpp
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
    PRIVATE Qt6::Quick Qt6::Network Qt6::QuickControls2
=======
    PRIVATE Qt6::Quick Qt6::Network
            OpenSSL::SSL OpenSSL::Crypto
            $<$<PLATFORM_ID:Windows>:ws2_32>
>>>>>>> Stashed changes
)

install(TARGETS appsecure_messenger
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
