cmake_minimum_required(VERSION 3.16)

project(secure_messenger VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Quick Network QuickControls2)

set(OPENSSL_ROOT_DIR "C:/msys64/ucrt64")
set(OPENSSL_INCLUDE_DIR "C:/msys64/ucrt64/include")

find_package(OpenSSL REQUIRED)

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
    src/network/TrustStore.cpp
    src/storage/LocalMessageStore.cpp
    src/utils/ClipboardHelper.cpp
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
    PRIVATE Qt6::Quick Qt6::Network Qt6::QuickControls2
            OpenSSL::SSL OpenSSL::Crypto
            $<$<PLATFORM_ID:Windows>:ws2_32>
)

# ── crypto_service PyInstaller bundle ─────────────────────────────────────────
cmake_path(GET CMAKE_CURRENT_SOURCE_DIR PARENT_PATH _CLIENT_DIR)
set(_CRYPTO_DIR  "${_CLIENT_DIR}/cryptography")
set(CRYPTO_DIST  "${_CRYPTO_DIR}/dist/crypto_service")

if(WIN32)
    set(_CRYPTO_EXE "crypto_service.exe")
else()
    set(_CRYPTO_EXE "crypto_service")
endif()

# ── Find the Python that has PyInstaller ──────────────────────────────────────
# Allow an explicit override: cmake -DPYINSTALLER_PYTHON=C:/path/to/python.exe
if(NOT PYINSTALLER_PYTHON)
    # 1. Try whatever CMake finds first
    find_package(Python3 QUIET COMPONENTS Interpreter)
    if(Python3_FOUND)
        execute_process(
            COMMAND "${Python3_EXECUTABLE}" -c "import PyInstaller"
            RESULT_VARIABLE _pi_rc OUTPUT_QUIET ERROR_QUIET)
        if(_pi_rc EQUAL 0)
            set(PYINSTALLER_PYTHON "${Python3_EXECUTABLE}")
        endif()
    endif()

    # 2. Fall back to common Windows install locations
    if(NOT PYINSTALLER_PYTHON AND WIN32)
        foreach(_hint
            "$ENV{LOCALAPPDATA}/Python/bin/python.exe"
            "$ENV{APPDATA}/Python/Scripts/python.exe"
            "$ENV{LOCALAPPDATA}/Programs/Python/Python312/python.exe"
            "$ENV{LOCALAPPDATA}/Programs/Python/Python311/python.exe"
        )
            if(EXISTS "${_hint}")
                execute_process(
                    COMMAND "${_hint}" -c "import PyInstaller"
                    RESULT_VARIABLE _pi_rc OUTPUT_QUIET ERROR_QUIET)
                if(_pi_rc EQUAL 0)
                    set(PYINSTALLER_PYTHON "${_hint}")
                    break()
                endif()
            endif()
        endforeach()
    endif()

    if(PYINSTALLER_PYTHON)
        set(PYINSTALLER_PYTHON "${PYINSTALLER_PYTHON}" CACHE STRING
            "Python executable used to rebuild the crypto_service bundle" FORCE)
    endif()
endif()

# ── Auto-rebuild bundle when Python sources change ────────────────────────────
if(PYINSTALLER_PYTHON)
    file(GLOB_RECURSE _CRYPTO_PY_SOURCES
        "${_CRYPTO_DIR}/crypto_service.py"
        "${_CRYPTO_DIR}/core/*.py"
    )

    add_custom_command(
        OUTPUT  "${CRYPTO_DIST}/${_CRYPTO_EXE}"
        COMMAND "${PYINSTALLER_PYTHON}" -m PyInstaller
                    --onedir --name crypto_service -y
                    "${_CRYPTO_DIR}/crypto_service.py"
        DEPENDS ${_CRYPTO_PY_SOURCES}
        WORKING_DIRECTORY "${_CRYPTO_DIR}"
        COMMENT "Rebuilding crypto_service bundle (PyInstaller)…"
        VERBATIM
    )

    add_custom_target(crypto_service_bundle
        DEPENDS "${CRYPTO_DIST}/${_CRYPTO_EXE}"
    )
    add_dependencies(appsecure_messenger crypto_service_bundle)

    message(STATUS "crypto_service auto-rebuild enabled (${PYINSTALLER_PYTHON})")
else()
    message(WARNING
        "PyInstaller not found — crypto_service bundle will NOT be rebuilt automatically.\n"
        "Start 'python main.py' in client/cryptography manually, or set -DPYINSTALLER_PYTHON=...")
endif()

# ── Copy bundle next to the app binary after every build ──────────────────────
add_custom_command(TARGET appsecure_messenger POST_BUILD
    COMMAND ${CMAKE_COMMAND}
        -DSRC_DIR=${CRYPTO_DIST}
        -DDST_DIR=$<TARGET_FILE_DIR:appsecure_messenger>/crypto_service
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/copy_crypto_bundle.cmake
    COMMENT "Copying crypto_service bundle to build output"
)

install(TARGETS appsecure_messenger
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

enable_testing()
add_subdirectory(tests)
