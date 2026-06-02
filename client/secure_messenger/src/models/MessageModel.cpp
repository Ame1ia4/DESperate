#include "MessageModel.h"

MessageModel::MessageModel(QObject *parent)
    : QAbstractListModel(parent)
{
}

int MessageModel::rowCount(
    const QModelIndex &parent
    ) const
{
    Q_UNUSED(parent)

    return static_cast<int>(
        m_messages.size()
        );
}

QVariant MessageModel::data(
    const QModelIndex &index,
    int role
    ) const
{
    if (!index.isValid())
        return {};

    const auto &msg =
        m_messages.at(index.row());

    switch (role) {

    case ContentRole:
        return msg.plaintext;

    case TimestampRole:
        return msg.timestamp;

    case VerificationRole:
        return static_cast<int>(
            msg.verificationState
            );

    case PlaintextRole:
        return msg.plaintext;

    case OutgoingRole:
        return msg.senderDeviceId == "self";

    case VerifiedRole:
        return msg.verificationState == VerificationState::Verified;

    case MessageIdRole:
        return msg.id;

    case RevokedRole:
        return msg.revoked;

    case IsDeletedRole:
        return msg.isDeleted;

    default:
        return {};
    }
}

QHash<int, QByteArray>
MessageModel::roleNames() const
{
    return {
        {ContentRole,      "content"},
        {TimestampRole,    "timestamp"},
        {VerificationRole, "verificationState"},
        {PlaintextRole,    "plaintext"},
        {OutgoingRole,     "outgoing"},
        {VerifiedRole,     "verified"},
        {MessageIdRole,    "messageId"},
        {RevokedRole,      "revoked"},
        {IsDeletedRole,    "isDeleted"}
    };
}

void MessageModel::addMessage(
    const DecryptedMessage &message
    )
{
    beginInsertRows(
        QModelIndex(),
        rowCount(),
        rowCount()
        );

    m_messages.push_back(message);

    endInsertRows();
}

void MessageModel::clear()
{
    beginResetModel();
    m_messages.clear();
    endResetModel();
}

void MessageModel::removeMessage(const QString& messageId)
{
    for (int i = 0; i < static_cast<int>(m_messages.size()); ++i) {
        if (m_messages[i].id == messageId) {
            beginRemoveRows(QModelIndex(), i, i);
            m_messages.erase(m_messages.begin() + i);
            endRemoveRows();
            return;
        }
    }
}

void MessageModel::markRevoked(const QString& messageId)
{
    for (int i = 0; i < static_cast<int>(m_messages.size()); ++i) {
        if (m_messages[i].id == messageId) {
            m_messages[i].revoked = true;
            const QModelIndex idx = index(i);
            emit dataChanged(idx, idx, {RevokedRole});
            return;
        }
    }
}

void MessageModel::markDeleted(const QString& messageId)
{
    for (int i = 0; i < static_cast<int>(m_messages.size()); ++i) {
        if (m_messages[i].id == messageId) {
            m_messages[i].isDeleted = true;
            const QModelIndex idx = index(i);
            emit dataChanged(idx, idx, {IsDeletedRole});
            return;
        }
    }
}

void MessageModel::updateMessageId(const QString& oldId, const QString& newId)
{
    if (oldId.isEmpty() || newId.isEmpty() || oldId == newId) return;
    for (auto& msg : m_messages) {
        if (msg.id == oldId) {
            msg.id = newId;
            return;
        }
    }
}