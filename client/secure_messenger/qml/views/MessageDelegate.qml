import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    required property string  plaintext
    required property bool    outgoing
    required property bool    verified
    required property string  messageId
    required property var     timestamp

    width:  ListView.view ? ListView.view.width : 0
    height: bubble.height + 16

    // ── Bubble ────────────────────────────────────────────────────────────────
    Rectangle {
        id: bubble

        // Max width 75% of the view, with padding for text
        property real contentMaxWidth: root.width * 0.75 - 28

        anchors.top:        parent.top
        anchors.topMargin:  8
        anchors.right:      outgoing ? parent.right     : undefined
        anchors.left:       outgoing ? undefined         : parent.left
        anchors.rightMargin: outgoing ? 8 : 0
        anchors.leftMargin:  outgoing ? 0 : 8

        // Message text drives the bubble size but will wrap at contentMaxWidth
        radius: 14
        // WhatsApp-ish colors: green for outgoing, light gray for incoming
        color: outgoing ? "#25D366" : "#ECECEC"
        border.color: outgoing ? "#1DA851" : "#D6D6D6"
        border.width: 1

        // Message text
        Text {
            id: msgText
            anchors {
                top:         parent.top
                left:        parent.left
                topMargin:   12
                leftMargin:  14
                rightMargin: 14
            }
            text:      plaintext
            wrapMode:  Text.WordWrap
            color:     outgoing ? "#FFFFFF" : "#0B0B0B"
            font.pixelSize: 14
            // Flexible width: prefer natural width but wrap at contentMaxWidth
            // Reserve space for the top-right menu button so text doesn't get overlapped
            width: Math.min(Math.max(contentMaxWidth - 36, 40), implicitWidth)
        }

        // Footer: timestamp + ticks
        Row {
            id: footer
            anchors {
                top:         msgText.bottom
                topMargin:   6
                right:       parent.right
                rightMargin: 14
                bottom:      parent.bottom
                bottomMargin: 8
            }
            spacing: 4
            layoutDirection: Qt.RightToLeft

            Text {
                visible: outgoing
                text:    verified ? "✓✓" : "✓"
                color:   verified ? "#FFFFFF" : "#B9EAC0"
                font.pixelSize: 11
                anchors.verticalCenter: parent.verticalCenter
            }

            Text {
                text: {
                    if (!timestamp) return ""
                    if (timestamp instanceof Date) return Qt.formatTime(timestamp, "hh:mm")
                    var s = timestamp.toString()
                    return s.length >= 16 ? s.substring(11, 16) : s
                }
                color:     outgoing ? "#FFFFFF" : "#4F4F4F"
                font.pixelSize: 11
                anchors.verticalCenter: parent.verticalCenter
            }
        }

        // Mini-menu button (top-right corner)
        Button {
            id: menuButton
            anchors.top: parent.top
            anchors.right: parent.right
            anchors.topMargin: 6
            anchors.rightMargin: 6
            implicitWidth: 28
            implicitHeight: 28
            background: Rectangle { color: "transparent" }
            contentItem: Rectangle {
                width: parent.implicitWidth
                height: parent.implicitHeight
                radius: width/2
                color: "transparent"
                border.color: "transparent"
                Text {
                    anchors.centerIn: parent
                    text: "⋯"
                    color: outgoing ? "#EAF9F0" : "#2B2B2B"
                    font.pixelSize: 14
                }
            }
            onClicked: actionMenu.popup()
        }

        // Right-click / press-and-hold → action menu
        MouseArea {
            anchors.fill: parent
            acceptedButtons: Qt.LeftButton | Qt.RightButton
            onClicked: function(mouse) {
                if (mouse.button === Qt.RightButton) actionMenu.popup()
            }
            onPressAndHold: actionMenu.popup()
        }

        // Bubble width depends on text width + padding
        width: Math.min(msgText.width + 28, root.width * 0.75)
        height: msgText.height + footer.height + 32
    }

    // ── Action menu ───────────────────────────────────────────────────────────
    Menu {
        id: actionMenu

        MenuItem {
            text: "Copy"
            onTriggered: Qt.copyToClipboard(plaintext)
        }

        MenuItem {
            text: "Forward"
            onTriggered: forwardBar.visible = !forwardBar.visible
        }

        MenuSeparator {}

        MenuItem {
            text: "Delete for me"
            onTriggered: messageController.deleteMessage(messageId)
        }

        MenuItem {
            visible: outgoing
            height:  outgoing ? implicitHeight : 0
            text:    "Revoke delivery"
            onTriggered: messageController.revokeMessage(
                messageId,
                conversationController.deviceIdForConversation(
                    conversationController.currentConversationId))
        }
    }

    // ── Inline forward bar ────────────────────────────────────────────────────
    Rectangle {
        id: forwardBar
        visible: false
        anchors { left: parent.left; right: parent.right; top: bubble.bottom; topMargin: 4 }
        height: visible ? 36 : 0
        color: "#173D28"
        radius: 8

        RowLayout {
            anchors { fill: parent; margins: 4 }
            spacing: 4

            TextField {
                id: forwardTo
                Layout.fillWidth: true
                placeholderText: "Forward to username…"
                placeholderTextColor: "#8AB89A"
                color: "#F5EDD6"
                font.pixelSize: 12
                background: Rectangle { color: "#2D6944"; radius: 6 }
            }

            Button {
                text: "Send"
                font.pixelSize: 12
                implicitHeight: 28
                background: Rectangle { color: "#4FAE7C"; radius: 6 }
                contentItem: Text {
                    text: parent.text; color: "#1B3B28"
                    font: parent.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment:   Text.AlignVCenter
                }
                onClicked: {
                    conversationController.createChat(forwardTo.text.trim())
                    forwardBar.visible = false
                    forwardTo.clear()
                }
            }

            Button {
                text: "✕"
                font.pixelSize: 12
                implicitWidth: 28; implicitHeight: 28
                background: Rectangle { color: "#5A3030"; radius: 6 }
                contentItem: Text {
                    text: parent.text; color: "#F8F0D7"
                    font: parent.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment:   Text.AlignVCenter
                }
                onClicked: { forwardBar.visible = false; forwardTo.clear() }
            }
        }
    }
}
