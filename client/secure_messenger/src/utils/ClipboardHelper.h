#pragma once

#include <QObject>

class ClipboardHelper : public QObject {
    Q_OBJECT
public:
    explicit ClipboardHelper(QObject* parent = nullptr) : QObject(parent) {}

    Q_INVOKABLE void copyText(const QString& text);
};
