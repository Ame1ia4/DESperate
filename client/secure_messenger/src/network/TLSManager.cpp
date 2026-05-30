#include "TLSManager.h"
#include "TrustStore.h"
#include "SocketUtils.h"

#include <QThread>
#include <QMutex>
#include <QMutexLocker>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>

#include <QSslConfiguration>
#include <QSslSocket>

// ── Worker ────────────────────────────────────────────────────────────────
// Runs on its own QThread. All blocking network/TLS work happens here.
// Main thread communicates via thread-safe enqueueWrite() / requestStop().

class TLSManager::Worker : public QObject
{
    Q_OBJECT

public:
    explicit Worker(const QString& caBundlePath, QObject* parent = nullptr)
        : QObject(parent)
        , m_caBundlePath(caBundlePath)
    {
#ifdef _WIN32
        WSADATA wsa{};
        if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            m_wsaInitFailed = true;
#else
        // SSL_write() uses write() internally; a broken socket raises SIGPIPE
        // which kills the process before the return value can be checked.
        ::signal(SIGPIPE, SIG_IGN);  // convert to EPIPE, handled via SSL_get_error()
#endif
    }

    ~Worker()
    {
        cleanup();
#ifdef _WIN32
        if (!m_wsaInitFailed)
            ::WSACleanup();
#endif
    }

    // Thread-safe: called from main thread while Worker::run() may be looping.
    void requestStop()
    {
        m_stopRequested.store(true, std::memory_order_relaxed);
    }

    void enqueueWrite(const QByteArray& data)
    {
        QMutexLocker lock(&m_writeMutex);
        if (m_writeBuffer.size() >= kMaxWriteBufferBytes) {
            m_bufferOverflow.store(true, std::memory_order_relaxed);
            return;
        }
        m_writeBuffer.append(data);
    }

public slots:
    // pinnedSha256: SHA-256 of the server's SPKI DER, or empty to skip pinning.
    void run(const QString& hostname, quint16 port, const QByteArray& pinnedSha256);

signals:
    void connected();
    void disconnected();
    void connectionFailed(const QString& error);
    void dataReceived(const QByteArray& data);

private:
    // Each helper emits connectionFailed + calls cleanup() on error and returns false.
    bool buildSslContext();
    bool tcpConnect(const QByteArray& hostBytes, quint16 port);
    bool performHandshake(const QByteArray& hostBytes, const QByteArray& pinnedSha256);
    void runIOLoop();

    void cleanup()
    {
        if (m_ssl) {
            // Two-phase shutdown: send our close_notify, then await peer's.
            if (SSL_shutdown(m_ssl) == 0)
                SSL_shutdown(m_ssl);
            SSL_free(m_ssl);
            m_ssl = nullptr;
        }
        if (m_ctx) {
            SSL_CTX_free(m_ctx);
            m_ctx = nullptr;
        }
        if (!sockInvalid(m_sock)) {
            closeSock(m_sock);
            m_sock = kInvalidSock;
        }
    }

    static QString collectOpenSSLErrors()
    {
        QString out;
        unsigned long e;
        char buf[256];
        while ((e = ERR_get_error()) != 0) {
            ERR_error_string_n(e, buf, sizeof(buf));
            if (!out.isEmpty()) out += "; ";
            out += QString::fromLatin1(buf);
        }
        return out.isEmpty() ? QStringLiteral("unknown OpenSSL error") : out;
    }

    static constexpr qsizetype kMaxWriteBufferBytes = 4 * 1024 * 1024; // 4 MB

    QString           m_caBundlePath;
    SSL_CTX*          m_ctx  = nullptr;
    SSL*              m_ssl  = nullptr;
    sock_t            m_sock = kInvalidSock;
    std::atomic<bool> m_stopRequested{false};
    std::atomic<bool> m_bufferOverflow{false};
    QMutex            m_writeMutex;
    QByteArray        m_writeBuffer;
#ifdef _WIN32
    bool              m_wsaInitFailed = false;
#endif
};

// ── Worker::run ───────────────────────────────────────────────────────────

void TLSManager::Worker::run(const QString& hostname, quint16 port,
                              const QByteArray& pinnedSha256)
{
    m_stopRequested.store(false, std::memory_order_relaxed);
    m_bufferOverflow.store(false, std::memory_order_relaxed);
    ERR_clear_error();

#ifdef _WIN32
    if (m_wsaInitFailed) {
        emit connectionFailed(QStringLiteral("WSAStartup failed"));
        return;
    }
#endif

    const QByteArray hostBytes = hostname.toUtf8();

    if (!buildSslContext())                         return;
    if (!tcpConnect(hostBytes, port))               return;
    if (!performHandshake(hostBytes, pinnedSha256)) return;

    emit connected();
    runIOLoop();
}

// ── Worker::buildSslContext ───────────────────────────────────────────────

bool TLSManager::Worker::buildSslContext()
{
    m_ctx = SSL_CTX_new(TLS_client_method());
    if (!m_ctx) {
        emit connectionFailed(
            QStringLiteral("SSL context creation failed: ") + collectOpenSSLErrors());
        return false;
    }

    // TLS 1.3 only — TLS 1.2 and earlier have known weaknesses (CBC padding
    // oracles, malleable MACs, no mandatory forward secrecy).
    SSL_CTX_set_min_proto_version(m_ctx, TLS1_3_VERSION);

    // Belt-and-suspenders: also disable via options flags
    SSL_CTX_set_options(m_ctx,
        SSL_OP_NO_SSLv2   | SSL_OP_NO_SSLv3   |
        SSL_OP_NO_TLSv1   | SSL_OP_NO_TLSv1_1 |
        SSL_OP_NO_TLSv1_2 | SSL_OP_NO_COMPRESSION);  // NO_COMPRESSION prevents CRIME

    // Strong AEAD ciphersuites only (AES-128 excluded: ~64-bit post-quantum security)
    if (SSL_CTX_set_ciphersuites(m_ctx,
            "TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256") != 1) {
        emit connectionFailed(
            QStringLiteral("Failed to set cipher suites: ") + collectOpenSSLErrors());
        cleanup();
        return false;
    }

    // Hybrid post-quantum key exchange: X25519 + ML-KEM-768, same as Chrome 131+.
    // Falls back to classical X25519 if the server doesn't support the hybrid group.
    // Requires OpenSSL 3.5+.
    if (SSL_CTX_set1_groups_list(m_ctx, "X25519MLKEM768:X25519") != 1) {
        emit connectionFailed(
            QStringLiteral("Failed to configure key exchange groups: ") + collectOpenSSLErrors());
        cleanup();
        return false;
    }

    // Require a valid peer certificate; fail if none is provided
    SSL_CTX_set_verify(m_ctx,
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    SSL_CTX_set_verify_depth(m_ctx, 5);

    if (!m_caBundlePath.isEmpty()) {
        const QByteArray path = m_caBundlePath.toUtf8();
        if (SSL_CTX_load_verify_locations(m_ctx, path.constData(), nullptr) != 1) {
            emit connectionFailed(
                QStringLiteral("Failed to load CA bundle: ") + collectOpenSSLErrors());
            cleanup();
            return false;
        }
    } else {
        if (SSL_CTX_set_default_verify_paths(m_ctx) != 1) {
            emit connectionFailed(
                QStringLiteral("Failed to load system CA store: ") + collectOpenSSLErrors());
            cleanup();
            return false;
        }
    }

    return true;
}

// ── Worker::tcpConnect ────────────────────────────────────────────────────

bool TLSManager::Worker::tcpConnect(const QByteArray& hostBytes, quint16 port)
{
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;   // accept IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    const QByteArray portBytes = QByteArray::number(port);
    struct addrinfo* addrList  = nullptr;

    const int gaErr = ::getaddrinfo(
        hostBytes.constData(), portBytes.constData(), &hints, &addrList);
    if (gaErr != 0) {
        emit connectionFailed(
            QString("DNS lookup failed for '%1': %2")
                .arg(QString::fromUtf8(hostBytes),
#ifdef _WIN32
                     QString::fromWCharArray(gai_strerror(gaErr))));
#else
                     QString::fromLocal8Bit(gai_strerror(gaErr))));
#endif
        cleanup();
        return false;
    }

    for (const struct addrinfo* ai = addrList; ai != nullptr; ai = ai->ai_next) {
        sock_t s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sockInvalid(s)) continue;

        setNonBlocking(s, true);
        const int connRet = ::connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        bool connOk = (connRet == 0);

        if (!connOk && connectInProgress()) {
            // FD_SETSIZE is 64 on Windows — safe here (single socket per Worker).
            // Do not use fd_set for multi-socket code on Windows without raising FD_SETSIZE.
            fd_set writefds;
            FD_ZERO(&writefds);
            FD_SET(s, &writefds);
            struct timeval tv{kConnectTimeoutSecs, 0};
            if (::select(static_cast<int>(s) + 1, nullptr, &writefds, nullptr, &tv) > 0) {
                int sockErr = 0;
                socklen_t errLen = sizeof(sockErr);
                ::getsockopt(s, SOL_SOCKET, SO_ERROR,
                             reinterpret_cast<char*>(&sockErr), &errLen);
                connOk = (sockErr == 0);
            }
        }
        if (connOk) {
            setNonBlocking(s, false); // restore blocking before handing off to TLS
            m_sock = s;
            break;
        }
        closeSock(s);
    }
    ::freeaddrinfo(addrList);

    if (sockInvalid(m_sock)) {
        emit connectionFailed(
            QString("TCP connection to %1:%2 failed")
                .arg(QString::fromUtf8(hostBytes)).arg(port));
        cleanup();
        return false;
    }

    return true;
}

// ── Worker::performHandshake ──────────────────────────────────────────────

bool TLSManager::Worker::performHandshake(const QByteArray& hostBytes,
                                           const QByteArray& pinnedSha256)
{
    m_ssl = SSL_new(m_ctx);
    if (!m_ssl) {
        emit connectionFailed(
            QStringLiteral("Failed to create SSL object: ") + collectOpenSSLErrors());
        cleanup();
        return false;
    }

    // Cast is safe: OpenSSL on Windows uses BIO_new_socket internally
    if (SSL_set_fd(m_ssl, static_cast<int>(m_sock)) != 1) {
        emit connectionFailed(
            QStringLiteral("Failed to bind socket to SSL object: ") + collectOpenSSLErrors());
        cleanup();
        return false;
    }

    // SNI extension — tells the server which virtual host we want
    if (SSL_set_tlsext_host_name(m_ssl, hostBytes.constData()) != 1) {
        emit connectionFailed(
            QStringLiteral("Failed to set SNI hostname: ") + collectOpenSSLErrors());
        cleanup();
        return false;
    }

    // Hostname verification: OpenSSL checks SAN then CN against this (RFC 6125)
    if (SSL_set1_host(m_ssl, hostBytes.constData()) != 1) {
        emit connectionFailed(
            QStringLiteral("Failed to configure hostname verification: ")
            + collectOpenSSLErrors());
        cleanup();
        return false;
    }

    if (SSL_connect(m_ssl) != 1) {
        const long ve = SSL_get_verify_result(m_ssl);
        const QString reason = (ve != X509_V_OK)
            ? QString("Certificate error: %1")
                  .arg(QString::fromLatin1(X509_verify_cert_error_string(ve)))
            : QStringLiteral("TLS handshake failed: ") + collectOpenSSLErrors();
        emit connectionFailed(reason);
        cleanup();
        return false;
    }

    // Explicit certificate verification check (defence in depth):
    // SSL_VERIFY_PEER already causes SSL_connect to abort on failure;
    // we verify the result code again to be explicit about the requirement.
    const long verifyResult = SSL_get_verify_result(m_ssl);
    if (verifyResult != X509_V_OK) {
        emit connectionFailed(
            QString("Certificate verification failed: %1")
                .arg(QString::fromLatin1(X509_verify_cert_error_string(verifyResult))));
        cleanup();
        return false;
    }

    // Certificate pinning (optional TOFU at transport level)
    if (!pinnedSha256.isEmpty()) {
        X509* cert = SSL_get_peer_certificate(m_ssl);
        if (!cert) {
            emit connectionFailed(QStringLiteral("No server certificate presented"));
            cleanup();
            return false;
        }
        unsigned char* spkiDer = nullptr;
        const int spkiLen = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &spkiDer);
        X509_free(cert);
        if (spkiLen <= 0) {
            OPENSSL_free(spkiDer); // may be non-null even on failure; free(nullptr) is safe
            emit connectionFailed(
                QStringLiteral("Failed to extract server public key for pinning"));
            cleanup();
            return false;
        }
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(spkiDer, static_cast<size_t>(spkiLen), hash);
        OPENSSL_free(spkiDer);

        const QByteArray actual(reinterpret_cast<const char*>(hash), SHA256_DIGEST_LENGTH);
        if (actual != pinnedSha256) {
            emit connectionFailed(
                QStringLiteral("Certificate pinning failed: server public key mismatch"));
            cleanup();
            return false;
        }
    }

    return true;
}

// ── Worker::runIOLoop ─────────────────────────────────────────────────────

void TLSManager::Worker::runIOLoop()
{
    char readBuf[16384];
    bool ioError = false;

    while (!m_stopRequested.load(std::memory_order_relaxed)) {
        if (m_bufferOverflow.load(std::memory_order_relaxed)) {
            ioError = true;
            break;
        }

        // Flush any pending outgoing data
        {
            QMutexLocker lock(&m_writeMutex);
            if (!m_writeBuffer.isEmpty()) {
                const int n = SSL_write(m_ssl,
                    m_writeBuffer.constData(),
                    static_cast<int>(m_writeBuffer.size()));
                if (n > 0) {
                    m_writeBuffer.remove(0, n);
                } else {
                    const int sslErr = SSL_get_error(m_ssl, n);
                    if (sslErr != SSL_ERROR_WANT_READ && sslErr != SSL_ERROR_WANT_WRITE)
                        ioError = true;
                    // WANT_READ/WANT_WRITE: leave data in buffer and retry next iteration
                }
            }
        }
        if (ioError) break;

        // 100 ms poll so the stop flag is checked regularly.
        // Note: only readfds is watched. If SSL_write returned WANT_WRITE the retry
        // will wait up to 100 ms rather than waking immediately when the socket
        // becomes writable — acceptable for a messaging app without sustained back-pressure.
        // FD_SETSIZE is 64 on Windows — safe here (single socket per Worker).
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(m_sock, &readfds);
        struct timeval tv{0, 100'000};
        const int sel = ::select(
            static_cast<int>(m_sock) + 1, &readfds, nullptr, nullptr, &tv);

        if (sel < 0) break;     // socket error
        if (sel == 0) continue; // timeout — recheck stop flag

        const int n = SSL_read(m_ssl, readBuf, static_cast<int>(sizeof(readBuf)));
        if (n > 0) {
            emit dataReceived(QByteArray(readBuf, n));
        } else if (n == 0) {
            break; // peer closed cleanly
        } else {
            const int sslErr = SSL_get_error(m_ssl, n);
            if (sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE)
                continue;
            break; // unrecoverable error
        }
    }

    // Collect error string before cleanup() so it isn't lost
    const QString errMsg = ioError
        ? (m_bufferOverflow.load()
               ? QStringLiteral("Write buffer exceeded 4 MB — connection dropped")
               : QStringLiteral("SSL write error: ") + collectOpenSSLErrors())
        : QString{};

    cleanup();

    if (ioError)
        emit connectionFailed(errMsg);
    else
        emit disconnected();
}

// ── TLSManager ────────────────────────────────────────────────────────────

TLSManager::TLSManager(TrustStore* trust, QObject* parent)
    : QObject(parent)
    , m_trust(trust)
{
    if (trust && !trust->isValid())
        m_initError = QString("CA bundle not found at path: %1").arg(trust->caBundlePath());

    const QString caPath = trust ? trust->caBundlePath() : QString{};
    m_worker = new Worker(caPath);
    m_thread = new QThread(this);
    m_worker->moveToThread(m_thread);

    connect(m_worker, &Worker::connected,
            this, [this] { m_connected.store(true); });
    connect(m_worker, &Worker::connected,
            this, &TLSManager::connected);

    connect(m_worker, &Worker::disconnected,
            this, [this] { m_connected.store(false); });
    connect(m_worker, &Worker::disconnected,
            this, &TLSManager::disconnected);

    connect(m_worker, &Worker::connectionFailed,
            this, [this] { m_connected.store(false); });
    connect(m_worker, &Worker::connectionFailed,
            this, &TLSManager::connectionFailed);

    connect(m_worker, &Worker::dataReceived,
            this, &TLSManager::dataReceived);

    connect(m_thread, &QThread::finished,
            m_worker, &QObject::deleteLater);

    m_thread->start();
}

TLSManager::~TLSManager()
{
    disconnectFromHost();
    m_thread->quit();
    if (!m_thread->wait(3000)) {
        // Thread did not stop gracefully; force-terminate to avoid a dangling Worker
        m_thread->terminate();
        m_thread->wait();
    }
}

void TLSManager::connectToHost(const QString& hostname, quint16 port)
{
    if (!m_initError.isEmpty()) {
        emit connectionFailed(m_initError);
        return;
    }

    // Capture the pinned hash at call time so it can't change mid-handshake
    const QByteArray pinned = m_pinnedSha256;
    QMetaObject::invokeMethod(m_worker, [w = m_worker, hostname, port, pinned] {
        w->run(hostname, port, pinned);
    }, Qt::QueuedConnection);
}

void TLSManager::disconnectFromHost()
{
    if (m_worker)
        m_worker->requestStop();
}

void TLSManager::write(const QByteArray& data)
{
    if (m_worker)
        m_worker->enqueueWrite(data);
}

bool TLSManager::isConnected() const
{
    return m_connected.load();
}

void TLSManager::setPinnedPublicKeyHash(const QByteArray& sha256)
{
    m_pinnedSha256 = sha256;
}

QSslConfiguration TLSManager::defaultConfig()
{
    QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
    cfg.setProtocol(QSsl::TlsV1_3OrLater);
    cfg.setPeerVerifyMode(QSslSocket::VerifyPeer);
    // TLS 1.3 cipher suites (AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM) are
    // always AEAD and cannot be weakened via Qt's cipher API — the protocol
    // version guarantee is sufficient here.
    return cfg;
}

// Required so Qt's moc processes the Worker class defined in this .cpp file
#include "TLSManager.moc"
