#include "ClipboardHelper.h"

#include <QGuiApplication>
#include <QClipboard>

void ClipboardHelper::copyText(const QString& text) {
    QClipboard *cb = QGuiApplication::clipboard();
    if (cb) cb->setText(text);
}
