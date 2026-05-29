#include "TLSManager.h"
#include "TrustStore.h"

<<<<<<< Updated upstream
#include <QFile>
#include <QSslCertificate>
#include <QSslSocket>

QSslConfiguration TLSManager::defaultConfig()
{
    QSslConfiguration ssl =
        QSslConfiguration::defaultConfiguration();

    ssl.setProtocol(QSsl::TlsV1_3);
    ssl.setPeerVerifyMode(QSslSocket::VerifyPeer);

    return ssl;
}

QSslConfiguration TLSManager::pinnedConfig(
    const QString& pemPath)
{
    QSslConfiguration ssl = defaultConfig();

    QFile file(pemPath);

    if (!file.open(QIODevice::ReadOnly)) {
        return ssl;
    }

    const QList<QSslCertificate> certs =
        QSslCertificate::fromDevice(
            &file, QSsl::Pem);

    if (!certs.isEmpty()) {
        ssl.setCaCertificates(certs);
    }

    return ssl;
}
=======
#include <QThread>
#include <QMutex>
#include <QMutexLocker>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
   using sock_t = SOCKET;
   static constexpr sock_t kInvalidSock = INVALID_SOCKET;
   static void closeSock(sock_t s)  { ::closesocket(s); }
   static bool sockInvalid(sock_t s){ return s == INVALID_SOCKET; }
#else
#  include <sys/socket.h>
#  include <netdb.h>
#  include <unistd.h>
   using sock_t = int;
   static constexpr sock_t kInvalidSock = -1;
   static void closeSock(sock_t s)  { ::close(s); }
   static bool sockInvalid(sock_t s){ return s < 0; }
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

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
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    }

    ~Worker()
    {
        cleanup();
#ifdef _WIN32
        WSACleanup();
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
        m_writeBuffer.append(data);
    }

public slots:
    // Invoked via QMetaObject::invokeMethod(Qt::QueuedConnection).
    // Blocks until the connection closes; emits signals back to main thread.
    void run(const QString& hostname, quint16 port);

signals:
    void connected();
    void disconnected();
    void connectionFailed(const QString& error);
    void dataReceived(const QByteArray& data);

private:
    void cleanup()
    {
        if (m_ssl) {
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

    QString           m_caBundlePath;
    SSL_CTX*          m_ctx  = nullptr;
    SSL*              m_ssl  = nullptr;
    sock_t            m_sock = kInvalidSock;
    std::atomic<bool> m_stopRequested{false};
    QMutex            m_writeMutex;
    QByteArray        m_writeBuffer;
};

void TLSManager::Worker::run(const QString& hostname, quint16 port)
{
    m_stopRequested.store(false, std::memory_order_relaxed);
    ERR_clear_error();

    // ── 1. Build SSL context ─────────────────────────────────────────────
    m_ctx = SSL_CTX_new(TLS_client_method());
    if (!m_ctx) {
        emit connectionFailed(
            QStringLiteral("SSL context creation failed: ") + collectOpenSSLErrors());
        return;
    }

    // TLS 1.2 minimum — TLS 1.0/1.1 deprecated by RFC 8996
    SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);

    // Belt-and-suspenders: also disable via options flags
    SSL_CTX_set_options(m_ctx,
        SSL_OP_NO_SSLv2        |
        SSL_OP_NO_SSLv3        |
        SSL_OP_NO_TLSv1        |
        SSL_OP_NO_TLSv1_1      |
        SSL_OP_NO_COMPRESSION);  // prevents CRIME attack

    // TLS 1.3 — strong AEAD ciphersuites only
    SSL_CTX_set_ciphersuites(m_ctx,
        "TLS_AES_256_GCM_SHA384:"
        "TLS_AES_128_GCM_SHA256:"
        "TLS_CHACHA20_POLY1305_SHA256");

    // TLS 1.2 — ECDHE + AEAD only; exclude null/anon/export/weak
    SSL_CTX_set_cipher_list(m_ctx,
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "!aNULL:!eNULL:!EXPORT:!RC4:!3DES:!MD5:!DSS");

    // Require a valid peer certificate; fail if none is provided
    SSL_CTX_set_verify(m_ctx,
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        nullptr);
    SSL_CTX_set_verify_depth(m_ctx, 5);

    // Load CA bundle (system store if no explicit path)
    if (!m_caBundlePath.isEmpty()) {
        const QByteArray path = m_caBundlePath.toUtf8();
        if (SSL_CTX_load_verify_locations(m_ctx, path.constData(), nullptr) != 1) {
            emit connectionFailed(
                QStringLiteral("Failed to load CA bundle: ") + collectOpenSSLErrors());
            cleanup();
            return;
        }
    } else {
        SSL_CTX_set_default_verify_paths(m_ctx);
    }

    // ── 2. DNS lookup ────────────────────────────────────────────────────
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;   // accept IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    const QByteArray hostBytes = hostname.toUtf8();
    const QByteArray portBytes = QByteArray::number(port);

    struct addrinfo* addrList = nullptr;
    const int gaErr = ::getaddrinfo(
        hostBytes.constData(), portBytes.constData(), &hints, &addrList);
    if (gaErr != 0) {
        emit connectionFailed(
            QString("DNS lookup failed for '%1': %2")
                .arg(hostname, QString::fromLocal8Bit(gai_strerror(gaErr))));
        cleanup();
        return;
    }

    // ── 3. TCP connect (iterate resolved addresses, use first that works) ─
    for (const struct addrinfo* ai = addrList; ai != nullptr; ai = ai->ai_next) {
        sock_t s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sockInvalid(s)) continue;
        if (::connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) {
            m_sock = s;
            break;
        }
        closeSock(s);
    }
    ::freeaddrinfo(addrList);

    if (sockInvalid(m_sock)) {
        emit connectionFailed(
            QString("TCP connection to %1:%2 failed").arg(hostname).arg(port));
        cleanup();
        return;
    }

    // ── 4. TLS handshake ─────────────────────────────────────────────────
    m_ssl = SSL_new(m_ctx);
    if (!m_ssl) {
        emit connectionFailed(
            QStringLiteral("Failed to create SSL object: ") + collectOpenSSLErrors());
        cleanup();
        return;
    }

    // Cast is safe: OpenSSL on Windows uses BIO_new_socket internally
    SSL_set_fd(m_ssl, static_cast<int>(m_sock));

    // SNI extension — tells the server which virtual host we want
    SSL_set_tlsext_host_name(m_ssl, hostBytes.constData());

    // Hostname verification: OpenSSL checks SAN then CN against this (RFC 6125)
    SSL_set1_host(m_ssl, hostBytes.constData());

    if (SSL_connect(m_ssl) != 1) {
        const long ve = SSL_get_verify_result(m_ssl);
        const QString reason = (ve != X509_V_OK)
            ? QString("Certificate error: %1")
                  .arg(QString::fromLatin1(X509_verify_cert_error_string(ve)))
            : QStringLiteral("TLS handshake failed: ") + collectOpenSSLErrors();
        emit connectionFailed(reason);
        cleanup();
        return;
    }

    // ── 5. Explicit certificate verification check (defence in depth) ────
    // SSL_VERIFY_PEER already causes SSL_connect to abort on failure;
    // we verify the result code again to be explicit about the requirement.
    const long verifyResult = SSL_get_verify_result(m_ssl);
    if (verifyResult != X509_V_OK) {
        emit connectionFailed(
            QString("Certificate verification failed: %1")
                .arg(QString::fromLatin1(
                    X509_verify_cert_error_string(verifyResult))));
        cleanup();
        return;
    }

    emit connected();

    // ── 6. I/O loop ──────────────────────────────────────────────────────
    char readBuf[16384];

    while (!m_stopRequested.load(std::memory_order_relaxed)) {
        // Flush any pending outgoing data
        {
            QMutexLocker lock(&m_writeMutex);
            if (!m_writeBuffer.isEmpty()) {
                SSL_write(m_ssl,
                    m_writeBuffer.constData(),
                    static_cast<int>(m_writeBuffer.size()));
                m_writeBuffer.clear();
            }
        }

        // 100 ms poll so the stop flag is checked regularly
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(m_sock, &readfds);
        struct timeval tv{0, 100'000};
        const int sel = ::select(
            static_cast<int>(m_sock) + 1, &readfds, nullptr, nullptr, &tv);

        if (sel < 0) break;   // socket error
        if (sel == 0) continue; // timeout

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

    cleanup();
    emit disconnected();
}

// ── TLSManager ────────────────────────────────────────────────────────────

TLSManager::TLSManager(TrustStore* trust, QObject* parent)
    : QObject(parent)
    , m_trust(trust)
{
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
    m_thread->wait(3000);
}

void TLSManager::connectToHost(const QString& hostname, quint16 port)
{
    QMetaObject::invokeMethod(m_worker, [w = m_worker, hostname, port] {
        w->run(hostname, port);
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

// Required so Qt's moc processes the Worker class defined in this .cpp file
#include "TLSManager.moc"
>>>>>>> Stashed changes
