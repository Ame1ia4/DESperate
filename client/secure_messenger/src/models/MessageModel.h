#pragma once

#include <QAbstractListModel>
#include <vector>

#include "../types/Types.h"

class MessageModel : public QAbstractListModel
{
    Q_OBJECT

public:
    explicit MessageModel(
        QObject *parent = nullptr
        );

    enum Roles {
        ContentRole = Qt::UserRole + 1,
        TimestampRole,
        VerificationRole,
        PlaintextRole,
        OutgoingRole,
        VerifiedRole,
        MessageIdRole,
        RevokedRole,
        IsDeletedRole
    };

    int rowCount(
        const QModelIndex &parent = QModelIndex()
        ) const override;

    QVariant data(
        const QModelIndex &index,
        int role
        ) const override;

    QHash<int, QByteArray>
    roleNames() const override;

    void addMessage(
        const DecryptedMessage &message
        );
    void clear();
    void removeMessage(const QString& messageId);
    void markRevoked(const QString& messageId);
    void markDeleted(const QString& messageId);
    void updateMessageId(const QString& oldId, const QString& newId);

private:
    std::vector<DecryptedMessage> m_messages;
};