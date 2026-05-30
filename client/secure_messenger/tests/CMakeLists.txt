find_package(Qt6 REQUIRED COMPONENTS Test Network)
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
