
#include "CryptoServiceClient.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QEventLoop>
#include <QFileInfo>
#include <QJsonDocument>
#include <QProcess>
#include <QThread>
#include <QUuid>

    CryptoServiceClient::CryptoServiceClient(
        QObject* parent)
    : QObject(parent)
{
}

CryptoServiceClient::~CryptoServiceClient()
{
    if (m_serviceProcess &&
        m_serviceProcess->state() != QProcess::NotRunning)
    {
        qDebug() << "[CryptoService] shutting down crypto service (pid"
                 << m_serviceProcess->processId() << ")";
        m_serviceProcess->terminate();
        if (!m_serviceProcess->waitForFinished(3000))
            m_serviceProcess->kill();
    }
    delete m_serviceProcess;
}

bool CryptoServiceClient::unlockKeystore(
    const QString& password)
{
    if (password.isEmpty()) {

        m_lastError =
            "Password required.";

        return false;
    }

    // Python handler accepts "password" key (matches both old and new handlers).
    const QJsonObject response =
        rpc(
            "unlock_keystore",
            {
                {"password", password}
            });

    const bool success =
        response.value("success")
            .toBool(false);

    if (!success) {

        m_lastError =
            response.value("error")
                .toString(
                    "Keystore unlock failed.");

        return false;
    }

    m_lastError.clear();

    return true;
}

QJsonObject
CryptoServiceClient::generateIdentityBundle(
    const QString& username,
    const QString& password,
    const QString& nonce)
{
    // Key generation + Argon2id keystore creation + ~100 KB response transfer.
    // 5 s is not enough on slow hardware; bump to 30 s for this call only.
    const int saved = m_rpcTimeoutMs;
    setRpcTimeoutMs(30000);

    const QJsonObject resp = rpc(
        "generate_identity_bundle",
        {
            {"username", username},
            {"password", password},
            {"nonce",    nonce}
        });

    setRpcTimeoutMs(saved);

    if (resp.contains(QStringLiteral("error"))) {
        // m_lastError already set by readResponse(); return empty so
        // callers can detect failure via isEmpty() as with other methods.
        return {};
    }

    return resp;
}

QString CryptoServiceClient::srpStart(
    const QString& username,
    const QString& password)
{
    const QJsonObject response =
        rpc("srp_start", {{"username", username}, {"password", password}});

    if (response.isEmpty()) {
        return {};
    }

    return response.value("A").toString();
}

QString CryptoServiceClient::srpChallenge(
    const QString& saltHex,
    const QString& bHex)
{
    const QJsonObject response =
        rpc("srp_challenge", {{"salt", saltHex}, {"B", bHex}});

    if (response.isEmpty()) {
        return {};
    }

    return response.value("M1").toString();
}

// Returns the session key hex on success, or empty string on failure.
QString CryptoServiceClient::srpVerify(
    const QString& m2Hex)
{
    const QJsonObject response =
        rpc("srp_verify", {{"M2", m2Hex}});

    if (response.isEmpty()) {
        return {};
    }

    if (!response.value("authenticated").toBool(false)) {
        m_lastError = response.value("error").toString("Authentication failed.");
        return {};
    }

    return response.value("session_key").toString();
}

bool CryptoServiceClient::hasSession(const QString& conversationId)
{
    const QJsonObject response =
        rpc("has_session", {{"conversation_id", conversationId}});
    return response.value("exists").toBool(false);
}

bool CryptoServiceClient::initiateSession(
    const QString& conversationId,
    const QByteArray& remoteBundleJson)
{
    const QJsonObject response =
        rpc(
            "initiate_session",
            {
                {"conversation_id", conversationId},
                {"remote_bundle",   QString::fromUtf8(remoteBundleJson)}
            });

    if (response.isEmpty()) {
        return false;
    }

    const bool success = response.value("success").toBool(false);
    if (!success) {
        m_lastError = response.value("error").toString("Session initiation failed.");
    }
    return success;
}

QJsonObject
CryptoServiceClient::encryptMessage(
    const QString& plaintext,
    const QString& /*recipientDeviceId*/,
    const QString& conversationId)
{
    return rpc(
        "encrypt_message",
        {
            {"plaintext",       plaintext},
            {"conversation_id", conversationId}
        });
}

QString CryptoServiceClient::decryptMessage(
    const QJsonObject& envelope)
{
    const QJsonObject response =
        rpc(
            "decrypt_message",
            {
                {"conversation_id",   envelope["conversation_id"]},
                {"ciphertext",        envelope["ciphertext"]},
                {"nonce",             envelope["nonce"]},
                {"initiation_bundle", envelope["initiation_bundle"]},
                {"sender_ik_sig_pub", envelope["sender_ik_sig_pub"]},
                {"sender_device_id",  envelope["sender_device_id"]},
            });

    if (response.contains("error")) {
        m_lastError = response.value("error").toString();
        return {};
    }

    return response.value("plaintext")
        .toString();
}

void CryptoServiceClient::encryptMessageAsync(
    const QString& requestId,
    const QByteArray& plaintext,
    const QString& recipientDeviceId,
    const QString& conversationId)
{
    QMetaObject::invokeMethod(
        this,
        [=]() {

            const QJsonObject response =
                encryptMessage(
                    QString::fromUtf8(
                        plaintext),
                    recipientDeviceId,
                    conversationId);

            if (response.isEmpty() ||
                response.contains("error")) {

                emit encryptFailed(
                    requestId,
                    m_lastError.isEmpty()
                        ? response.value("error").toString("Encryption failed.")
                        : m_lastError);

                return;
            }

            emit encryptCompleted(
                requestId,
                response);
        },
        Qt::QueuedConnection);
}

void CryptoServiceClient::decryptMessageAsync(
    const QString& requestId,
    const QJsonObject& envelope)
{
    QMetaObject::invokeMethod(
        this,
        [=]() {

            const QString plaintext =
                decryptMessage(
                    envelope);

            if (plaintext.isEmpty()) {

                emit decryptFailed(
                    requestId,
                    m_lastError.isEmpty()
                        ? "Decryption failed."
                        : m_lastError);

                return;
            }

            emit decryptCompleted(
                requestId,
                plaintext);
        },
        Qt::QueuedConnection);
}

QString CryptoServiceClient::lastError() const
{
    return m_lastError;
}

void CryptoServiceClient::setRpcTimeoutMs(
    int timeoutMs)
{
    if (timeoutMs <= 0) {
        return;
    }

    m_rpcTimeoutMs = timeoutMs;
}

QJsonObject CryptoServiceClient::rpc(
    const QString& method,
    const QJsonObject& params)
{
    if (!ensureConnected()) {
        return {};
    }

    // Drain any bytes left over from a previous timed-out call so they
    // don't get mistaken for the response to this request.
    if (m_socket.bytesAvailable() > 0) {
        qDebug() << "[CryptoService] draining" << m_socket.bytesAvailable()
                 << "stale bytes before" << method;
        m_socket.readAll();
    }

    const QString requestId = QUuid::createUuid().toString();

    QJsonObject request;
    request["id"]     = requestId;
    request["method"] = method;
    request["params"] = params;

    const QByteArray payload =
        QJsonDocument(request)
            .toJson(
                QJsonDocument::Compact);

    if (!writeRequest(payload)) {
        return {};
    }

    return readResponse(requestId);
}

bool CryptoServiceClient::ensureConnected()
{
    if (m_socket.state() ==
        QAbstractSocket::ConnectedState) {

        return true;
    }

    m_socket.connectToHost(
        m_serviceHost,
        m_servicePort);

    if (m_socket.waitForConnected(
            m_rpcTimeoutMs)) {

        return true;
    }

    if (!m_serviceStarted) {

        if (!startLocalCryptoService()) {

            m_lastError =
                "Unable to start crypto service.";

            return false;
        }

        m_serviceStarted = true;

        // Python needs time to import modules and bind the socket.
        // ECONNREFUSED returns immediately (not after the timeout), so we
        // must retry with small delays rather than one long waitForConnected.
        const int retryIntervalMs = 300;
        const int maxWaitMs       = 10000;
        int elapsed               = 0;
        while (elapsed < maxWaitMs) {
            QThread::msleep(retryIntervalMs);
            elapsed += retryIntervalMs;

            m_socket.abort();
            m_socket.connectToHost(m_serviceHost, m_servicePort);
            if (m_socket.waitForConnected(retryIntervalMs)) {
                return true;
            }
        }
    }

    m_lastError =
        m_socket.errorString();

    return false;
}

bool CryptoServiceClient::startLocalCryptoService()
{
    const QString script =
        locateServiceScript();

    if (script.isEmpty()) {

        m_lastError =
            "Crypto service script missing.";

        return false;
    }

    m_serviceProcess = new QProcess();
    m_serviceProcess->start(script);

    if (!m_serviceProcess->waitForStarted(3000)) {
        m_lastError = "Crypto service failed to start.";
        delete m_serviceProcess;
        m_serviceProcess = nullptr;
        return false;
    }

    qDebug() << "[CryptoService] started (pid"
             << m_serviceProcess->processId() << ")";
    return true;
}

QString CryptoServiceClient::locateServiceScript()
    const
{
    const QString basePath =
        QCoreApplication
        ::applicationDirPath();

#ifdef Q_OS_WIN
    const QString exe = QStringLiteral(".exe");
#else
    const QString exe = QStringLiteral("");
#endif

    const QString bundled =
        basePath + "/crypto_service/crypto_service" + exe;

    if (QFileInfo::exists(bundled)) {
        return bundled;
    }

    return {};
}

bool CryptoServiceClient::writeRequest(
    const QByteArray& payload)
{
    const QByteArray framed =
        payload + '\n';

    if (m_socket.write(framed) == -1) {

        m_lastError =
            m_socket.errorString();

        return false;
    }

    if (!m_socket.waitForBytesWritten(
            m_rpcTimeoutMs)) {

        m_lastError =
            "Timed out writing request.";

        return false;
    }

    return true;
}

QJsonObject
CryptoServiceClient::readResponse(const QString& expectedId)
{
    // JSON-RPC 2.0: clients must correlate responses by "id".
    // Best practice for a synchronous client is to keep reading lines until
    // the matching id arrives rather than giving up on the first mismatch:
    //
    //   • id=null (empty string in Qt)  — server parse error for a line it
    //     couldn't decode (e.g. empty line sent during connection setup by
    //     the asyncio transport).  Per spec: discard, it belongs to no request.
    //   • id=wrong uuid               — stale response from a prior timed-out
    //     call whose reply arrived late.  Discard, keep waiting.
    //   • id=expected uuid            — our response; use it.
    //
    // Each waitForReadyRead resets the per-segment deadline; for large
    // responses (~100 KB identity bundles with ML-KEM OPKs) several TCP
    // segments arrive before canReadLine() becomes true, so we loop.
    for (;;) {
        while (!m_socket.canReadLine()) {
            if (!m_socket.waitForReadyRead(m_rpcTimeoutMs)) {
                m_lastError = "Timed out waiting for crypto service response.";
                qDebug() << "[CryptoService] readResponse timed out after"
                         << m_rpcTimeoutMs << "ms"
                         << "(expectedId:" << expectedId << ")";
                return {};
            }
        }

        const QByteArray responseBytes =
            m_socket.readLine();

        const auto document =
            QJsonDocument::fromJson(
                responseBytes);

        if (!document.isObject()) {
            m_lastError = "Invalid RPC response (not a JSON object). First 200 bytes: "
                          + QString::fromUtf8(responseBytes.left(200));
            qDebug() << "[CryptoService] readResponse: parse error —" << m_lastError;
            return {};
        }

        const QJsonObject response =
            document.object();

        if (!expectedId.isEmpty()) {
            const QString responseId = response.value("id").toString();
            const bool hasError      = response.contains(QStringLiteral("error"));

            if (responseId.isEmpty() && hasError) {
                // JSON-RPC parse error: server got garbage on the wire
                // (e.g. an empty line sent by the asyncio transport on connect).
                // The response for our actual request will arrive next.
                qDebug() << "[CryptoService] readResponse: discarding null-id error:"
                         << response.value("error").toString();
                continue;
            }

            if (!responseId.isEmpty() && responseId != expectedId) {
                // Non-null id that doesn't match — stale response from a
                // previous timed-out RPC call.
                qDebug() << "[CryptoService] readResponse: discarding stale response"
                         << "(got id:" << responseId
                         << ", expected:" << expectedId << ")";
                continue;
            }

            // Accept: id matches, OR id is null but no error field
            // (old binary compat — pre-id-field builds omit "id" from results).
            if (responseId.isEmpty()) {
                qDebug() << "[CryptoService] readResponse: accepted null-id result"
                         << "(binary may be stale — rebuild from current crypto_service.py)";
            }
        }

        if (response.contains("error")) {
            m_lastError = response.value("error").toString();
            qDebug() << "[CryptoService] readResponse: service error —" << m_lastError;
            return response;
        }

        return response;
    }
}
