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
            text: conversationController.currentConversationId === ""
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

            model: conversationController.messages

            delegate: MessageDelegate {
                plaintext: model.plaintext
                outgoing: model.outgoing
                verified: model.verified
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8

            TextField {
                id: messageField
                Layout.fillWidth: true
                placeholderText: "Type a message"
                placeholderTextColor: "#C9D4C5"
                enabled: conversationController.currentConversationId !== ""
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
                enabled: conversationController.currentConversationId !== ""
                background: Rectangle {
                    color: "#4FAE7C"
                    radius: 10
                }
                onClicked: {
                    conversationController.sendMessage(
                        conversationController.currentConversationId,
                        messageField.text)

                    messageField.clear()
                }
            }
        }
    }
}