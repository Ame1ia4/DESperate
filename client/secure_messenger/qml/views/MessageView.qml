import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    color: "#1E4C33"

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 10

        Text {
            Layout.fillWidth: true
            text: !conversationController || conversationController.currentConversationId === ""
                  ? "Select a chat to start messaging"
                  : "Conversation: " + conversationController.currentConversationId
            color: "#F5EDD6"
            elide: Text.ElideRight
            font.pixelSize: 18
            font.bold: true
        }

        ListView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true

            model: conversationController ? conversationController.messages : null

            delegate: MessageDelegate {
                plaintext: model.plaintext
                outgoing: model.outgoing
                verified: model.verified
            }
        }

        Text {
            Layout.fillWidth: true
            visible: conversationController
                     && conversationController.currentConversationId !== ""
                     && !conversationController.sessionReady
            text: "Establishing secure channel…"
            color: "#A0C8B0"
            font.pixelSize: 12
            horizontalAlignment: Text.AlignHCenter
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8

            property bool canSend: conversationController
                                   && conversationController.currentConversationId !== ""
                                   && conversationController.sessionReady

            TextField {
                id: messageField
                Layout.fillWidth: true
                placeholderText: "Type a message"
                placeholderTextColor: "#C9D4C5"
                enabled: parent.canSend
                background: Rectangle {
                    color: "#2D6944"
                    radius: 10
                    border.color: "#4FAE7C"
                    border.width: 1
                }
                color: "#F5EDD6"
            }

            Button {
                text: "Send"
                enabled: parent.canSend
                background: Rectangle {
                    color: enabled ? "#4FAE7C" : "#3A5A47"
                    radius: 10
                }
                onClicked: {
                    messageController.sendText(
                        conversationController.currentConversationId,
                        messageField.text)

                    messageField.clear()
                }
            }
        }
    }
}