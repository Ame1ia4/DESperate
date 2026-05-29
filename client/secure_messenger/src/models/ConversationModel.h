#pragma once

#include <QAbstractListModel>
#include <QDateTime>
#include <QObject>
#include <QString>
#include <QVector>

struct ConversationItem
{
    QString conversationId;
    QString participant;
    QString deviceId;
    QString lastMessage;
    QString fingerprint;
    QDateTime updatedAt;
    int unreadCount;
    bool verified;
};

class ConversationModel final : public QAbstractListModel
{
    Q_OBJECT

public:
    enum ConversationRoles {
        ConversationIdRole = Qt::UserRole + 1,
        ParticipantRole,
        LastMessageRole,
        FingerprintRole,
        UpdatedAtRole,
        UnreadCountRole,
        VerifiedRole
    };

    explicit ConversationModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;

    QVariant data(const QModelIndex& index,
                  int role = Qt::DisplayRole) const override;

    QHash<int, QByteArray> roleNames() const override;

    void setConversations(const QVector<ConversationItem>& items);

    Q_INVOKABLE QString fingerprintForConversation(const QString& id) const;
    Q_INVOKABLE bool setFingerprintForConversation(const QString& id,
                                                   const QString& fingerprint,
                                                   bool verified);

private:
    QVector<ConversationItem> m_conversations;
};