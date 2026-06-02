find_package(Qt6 REQUIRED COMPONENTS Test Network)
find_package(OpenSSL REQUIRED)

# ── TrustStore unit tests (SSL CA-path variant) ───────────────────────────
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

# ── LocalMessageStore unit tests ──────────────────────────────────────────
# Covers: decrypted/envelope storage, deduplication, filtering,
# clearConversation, clearAll, JSON parsing, E2EE ciphertext≠plaintext invariant.
qt_add_executable(tst_localmessagestore
    tst_localmessagestore.cpp
    ../src/storage/LocalMessageStore.cpp
)
target_include_directories(tst_localmessagestore PRIVATE ..)
target_link_libraries(tst_localmessagestore PRIVATE Qt6::Test)
add_test(NAME LocalMessageStore COMMAND tst_localmessagestore)

# ── MessageModel unit tests ───────────────────────────────────────────────
# Covers: all QML data roles, outgoing/verified flags, rowsInserted/modelReset
# signals, invalid-index guards, VerificationRole type safety.
qt_add_executable(tst_messagemodel
    tst_messagemodel.cpp
    ../src/models/MessageModel.cpp
)
target_include_directories(tst_messagemodel PRIVATE ..)
target_link_libraries(tst_messagemodel PRIVATE Qt6::Test)
add_test(NAME MessageModel COMMAND tst_messagemodel)

# ── ConversationModel unit tests ──────────────────────────────────────────
# Covers: setConversations, all roles, fingerprintForConversation,
# setFingerprintForConversation (dataChanged roles), invalid-index guards.
qt_add_executable(tst_conversationmodel
    tst_conversationmodel.cpp
    ../src/models/ConversationModel.cpp
)
target_include_directories(tst_conversationmodel PRIVATE ..)
target_link_libraries(tst_conversationmodel PRIVATE Qt6::Test)
add_test(NAME ConversationModel COMMAND tst_conversationmodel)

# ── TOFU TrustStore unit tests ────────────────────────────────────────────
# Covers: first-seen pinning, same-fingerprint acceptance, mismatch detection,
# fingerprintPinned / fingerprintMismatch signals, multi-user isolation.
# Maps to Cryptography rubric: Key Establishment & Sender Authentication (TOFU).
qt_add_executable(tst_tofu
    tst_tofu.cpp
    ../src/storage/TrustStore.cpp
)
target_include_directories(tst_tofu PRIVATE ..)
target_link_libraries(tst_tofu PRIVATE Qt6::Test)
add_test(NAME TOFU COMMAND tst_tofu)

# ── MessageController unit tests ──────────────────────────────────────────
# Covers: sendMessage/sendText guard conditions (Improper Input Validation),
# encrypt/decrypt signal routing, delete/revoke delegation, forward/copy/download
# use cases via LocalMessageStore.
# Uses TestableCryptoServiceClient (derived class that emits signals without
# requiring the Python crypto service) and TrackingApiClient (call counting).
qt_add_executable(tst_messagecontroller
    tst_messagecontroller.cpp
    ../src/controllers/MessageController.cpp
    ../src/controllers/ConversationController.cpp
    ../src/models/ConversationModel.cpp
    ../src/models/MessageModel.cpp
    ../src/storage/LocalMessageStore.cpp
    ../src/storage/SessionStore.cpp
    ../src/storage/TrustStore.cpp
    ../src/services/ApiClient.cpp
    ../src/services/CryptoServiceClient.cpp
)
target_include_directories(tst_messagecontroller PRIVATE ..)
target_link_libraries(tst_messagecontroller
    PRIVATE Qt6::Test Qt6::Network
            OpenSSL::SSL OpenSSL::Crypto
            $<$<PLATFORM_ID:Windows>:ws2_32>
)
add_test(NAME MessageController COMMAND tst_messagecontroller)
