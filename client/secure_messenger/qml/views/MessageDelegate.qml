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

    width:  ListView.view.width
    height: row.height + 16

    // ── Layout: avatar space + bubble, mirrored for outgoing ─────────────────
    Row {
        id: row
        anchors {
            left:   parent.left
            right:  parent.right
            top:    parent.top
            topMargin: 8
            leftMargin:  outgoing ? parent.width * 0.22 : 8
            rightMargin: outgoing ? 8 : parent.width * 0.22
        }
        spacing: 0

        // ── Bubble ────────────────────────────────────────────────────────────
        Rectangle {
            id: bubble
            width:  parent.width
            radius: 16
            color:  outgoing ? "#3C8A5A" : "#2A5B45"

            // Shadow effect
            layer.enabled: true
            layer.effect: null

            Column {
                anchors {
                    fill: parent
                    margins: 12
                }
                spacing: 6

                // Message text
                Text {
                    width: parent.width
                    text:  plaintext
                    wrapMode: Text.Wrap
                    color: "#F8F0D7"
                    font.pixelSize: 14
                }

                // Footer: timestamp + status
                Row {
                    width: parent.width
                    spacing: 6
                    layoutDirection: outgoing ? Qt.RightToLeft : Qt.LeftToRight

                    Text {
                        text: timestamp instanceof Date
                              ? Qt.formatTime(timestamp, "hh:mm")
                              : (typeof timestamp === "string" ? timestamp.substring(11, 16) : "")
                        color:     "#A8D5B5"
                        font.pixelSize: 10
                    }

                    Text {
                        visible: outgoing
                        text:    verified ? "✓✓" : "✓"
                        color:   verified ? "#7EE8A2" : "#A8D5B5"
                        font.pixelSize: 10
                    }
                }
            }

            // Right-click / press-and-hold to open action menu
            MouseArea {
                anchors.fill: parent
                acceptedButtons: Qt.LeftButton | Qt.RightButton
                onClicked: function(mouse) {
                    if (mouse.button === Qt.RightButton)
                        actionMenu.popup()
                }
                onPressAndHold: actionMenu.popup()
            }
        }
    }

    // ── Action menu ───────────────────────────────────────────────────────────
    Menu {
        id: actionMenu

        MenuItem {
            text: "Copy"
            onTriggered: Clipboard.copy !== undefined
                         ? Clipboard.copy(plaintext)
                         : Qt.copyToClipboard(plaintext)
        }

        MenuItem {
            text: "Forward"
            onTriggered: forwardField.visible = true
        }

        MenuSeparator {}

        MenuItem {
            text:    "Delete for me"
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

    // ── Inline forward bar (shown after "Forward") ────────────────────────────
    Rectangle {
        id: forwardField
        visible: false
        anchors {
            left:  parent.left
            right: parent.right
            top:   row.bottom
            topMargin: 4
        }
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
                    text: parent.text
                    color: "#1B3B28"
                    font: parent.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                onClicked: {
                    // Forward = open/create a conversation and send the same text
                    conversationController.createChat(forwardTo.text.trim())
                    forwardField.visible = false
                    forwardTo.clear()
                }
            }

            Button {
                text: "✕"
                font.pixelSize: 12
                implicitWidth: 28
                implicitHeight: 28
                background: Rectangle { color: "#5A3030"; radius: 6 }
                contentItem: Text {
                    text: parent.text
                    color: "#F8F0D7"
                    font: parent.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                onClicked: { forwardField.visible = false; forwardTo.clear() }
            }
        }
    }
}
