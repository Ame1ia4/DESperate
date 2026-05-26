#pragma once

#include <QObject>
#include <QSqlDatabase>
#include <QJsonObject>

class LocalMessageStore : public QObject
{
    Q_OBJECT

public:
    explicit LocalMessageStore(QObject* parent = nullptr);

    void initialize();

    void storeOutgoingMessage(
        const QJsonObject& envelope
        );

private:
    QSqlDatabase m_db;
};