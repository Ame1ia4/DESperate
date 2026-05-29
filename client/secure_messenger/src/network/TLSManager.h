#pragma once

<<<<<<< Updated upstream
#include <QSslConfiguration>
#include <QString>

class TLSManager
{
public:
    TLSManager() = default;

    // Returns a QSslConfiguration enforcing TLS 1.3 with peer
    // verification using the system CA store.  Pass this to every
    // QNetworkRequest via setSslConfiguration().
    static QSslConfiguration defaultConfig();

    // Same as defaultConfig() but also pins the PEM certificate at
    // pemPath.  Use this to pin the project server's certificate for
    // an additional layer of TOFU at the transport level.
    static QSslConfiguration pinnedConfig(const QString& pemPath);
};
=======
#include <QObject>
#include <atomic>

class TrustStore;

class TLSManager : public QObject
{
    Q_OBJECT
>>>>>>> Stashed changes

public:
    explicit TLSManager(TrustStore* trust, QObject* parent = nullptr);
    ~TLSManager();

    void connectToHost(const QString& hostname, quint16 port);
    void disconnectFromHost();
    void write(const QByteArray& data);
    bool isConnected() const;

signals:
    void connected();
    void disconnected();
    void connectionFailed(const QString& error);
    void dataReceived(const QByteArray& data);

private:
    class Worker;

    TrustStore*          m_trust   = nullptr;
    QThread*             m_thread  = nullptr;
    Worker*              m_worker  = nullptr;
    std::atomic<bool>    m_connected{false};
};
