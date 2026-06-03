#include "ConversationModel.h"

ConversationModel::ConversationModel(QObject* parent)
    : QAbstractListModel(parent)
{
}

int ConversationModel::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid()) {
        return 0;
    }

    return m_conversations.size();
}

QVariant ConversationModel::data(const QModelIndex& index,
                                 int role) const
{
    if (!index.isValid() || index.row() >= static_cast<int>(m_conversations.size())) {
        return {};
    }

    const auto& item = m_conversations.at(index.row());

    switch (role) {
    case ConversationIdRole:
        return item.conversationId;

    case ParticipantRole:
        return item.participant;

    case LastMessageRole:
        return item.lastMessage;

    case FingerprintRole:
        return item.fingerprint;

    case UpdatedAtRole:
        return item.updatedAt;

    case UnreadCountRole:
        return item.unreadCount;

    case VerifiedRole:
        return item.verified;

    default:
        return {};
    }
}

QHash<int, QByteArray> ConversationModel::roleNames() const
{
    return {
        {ConversationIdRole, "conversationId"},
        {ParticipantRole, "participant"},
        {LastMessageRole, "lastMessage"},
        {FingerprintRole, "fingerprint"},
        {UpdatedAtRole, "updatedAt"},
        {UnreadCountRole, "unreadCount"},
        {VerifiedRole, "verified"}
    };
}

void ConversationModel::setConversations(
    const std::vector<ConversationItem>& items)
{
    beginResetModel();
    m_conversations = items;
    endResetModel();
}

QString ConversationModel::fingerprintForConversation(
    const QString& id) const
{
    for (const auto& item : m_conversations) {
        if (item.conversationId == id) {
            return item.fingerprint;
        }
    }

    return {};
}

bool ConversationModel::setFingerprintForConversation(
    const QString& id,
    const QString& fingerprint,
    bool verified)
{
    for (int row = 0; row < static_cast<int>(m_conversations.size()); ++row) {
        auto& item = m_conversations[row];
        if (item.conversationId == id) {
            item.fingerprint = fingerprint;
            item.verified = verified;

            const QModelIndex idx = index(row);
            emit dataChanged(idx,
                             idx,
                             {FingerprintRole, VerifiedRole});
            return true;
        }
    }

    return false;
}