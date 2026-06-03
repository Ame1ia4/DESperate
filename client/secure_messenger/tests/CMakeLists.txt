find_package(Qt6 REQUIRED COMPONENTS Test Network Gui Quick)
find_package(OpenSSL REQUIRED)

# ── TrustStore unit tests ─────────────────────────────────────────────────
qt_add_executable(tst_truststore tst_truststore.cpp
    ../src/network/TrustStore.cpp
)
target_include_directories(tst_truststore PRIVATE ../src/network)
target_link_libraries(tst_truststore PRIVATE Qt6::Test)
add_test(NAME TrustStore COMMAND tst_truststore)

# ── TLSManager unit tests ─────────────────────────────────────────────────
qt_add_executable(tst_tlsmanager tst_tlsmanager.cpp
    ../src/network/TLSManager.cpp
    ../src/network/TrustStore.cpp
)
target_include_directories(tst_tlsmanager PRIVATE ../src/network)
target_link_libraries(tst_tlsmanager
    PRIVATE Qt6::Test Qt6::Network
            OpenSSL::SSL OpenSSL::Crypto
            $<$<PLATFORM_ID:Windows>:ws2_32>
)
add_test(NAME TLSManager COMMAND tst_tlsmanager)

# ── CopyMerkleRoot unit tests ─────────────────────────────────────────────
qt_add_executable(tst_copymerkleroot
    tst_copymerkleroot.cpp
    ../src/controllers/MessageController.cpp
    ../src/controllers/ConversationController.cpp
    ../src/controllers/AuthController.cpp
    ../src/services/ApiClient.cpp
    ../src/services/CryptoServiceClient.cpp
    ../src/models/MessageModel.cpp
    ../src/models/ConversationModel.cpp
    ../src/models/UserModel.cpp
    ../src/models/DeviceModel.cpp
    ../src/models/SessionModel.cpp
    ../src/network/TLSManager.cpp
    ../src/network/TrustStore.cpp
    ../src/storage/TrustStore.cpp
    ../src/storage/LocalMessageStore.cpp
    ../src/storage/SessionStore.cpp
    ../src/utils/ClipboardHelper.cpp
)
target_include_directories(tst_copymerkleroot PRIVATE ..)
target_link_libraries(tst_copymerkleroot
    PRIVATE Qt6::Test Qt6::Network Qt6::Gui Qt6::Quick
            OpenSSL::SSL OpenSSL::Crypto
            $<$<PLATFORM_ID:Windows>:ws2_32>
)
add_test(NAME CopyMerkleRoot COMMAND tst_copymerkleroot)
