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

    default:
        return {};
    }
}

QHash<int, QByteArray>
MessageModel::roleNames() const
{
    return {
        {ContentRole, "content"},
        {TimestampRole, "timestamp"},
        {VerificationRole, "verificationState"},
        {PlaintextRole, "plaintext"},
        {OutgoingRole, "outgoing"},
        {VerifiedRole, "verified"}
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