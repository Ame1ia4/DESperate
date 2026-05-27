#pragma once

#include <QString>
#include <QDateTime>
#include <QByteArray>

enum class VerificationState {
    Pending,
    Verified,
    Failed
};

struct MessageEnvelope {
    QString id;
    QString conversationId;
    QString senderDeviceId;
    QByteArray ciphertext;
    QByteArray nonce;
    QByteArray associatedData;
    QString txHash;
    QString merkleRoot;
    QDateTime timestamp;
    VerificationState verificationState = VerificationState::Pending;
    bool isDeleted = false;
};

struct DecryptedMessage {
    QString id;
    QString conversationId;
    QString senderDeviceId;
    QString plaintext;
    QDateTime timestamp;
    VerificationState verificationState = VerificationState::Pending;
    bool isDeleted = false;
};

struct Conversation {
    QString id;

    QString title;

    QString lastMessagePreview;

    QDateTime updatedAt;
};

struct User {
    QString id;

    QString username;
};