#pragma once

#include <QObject>
#include <atomic>

class TrustStore;

class TLSManager : public QObject
{
    Q_OBJECT

public:
    explicit TLSManager(TrustStore* trust, QObject* parent = nullptr);
    ~TLSManager();

    void connectToHost(const QString& hostname, quint16 port);
    void disconnectFromHost();
    void write(const QByteArray& data);
    bool isConnected() const;

    // Set a SHA-256 hash of the server's SubjectPublicKeyInfo (SPKI) to pin.
    // Must be called before connectToHost(). Empty array disables pinning.
    void setPinnedPublicKeyHash(const QByteArray& sha256);

signals:
    void connected();
    void disconnected();
    void connectionFailed(const QString& error);
    void dataReceived(const QByteArray& data);

private:
    class Worker;

    TrustStore*          m_trust        = nullptr;
    QThread*             m_thread       = nullptr;
    Worker*              m_worker       = nullptr;
    std::atomic<bool>    m_connected{false};
    QByteArray           m_pinnedSha256;
};
