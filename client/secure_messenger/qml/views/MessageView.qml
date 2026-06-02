import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    color: "#1E4C33"

    // Download status toast
    Rectangle {
        id: downloadToast
        visible: false
        anchors { bottom: parent.bottom; horizontalCenter: parent.horizontalCenter; bottomMargin: 16 }
        width: downloadToastText.implicitWidth + 32
        height: 36
        radius: 8
        color: downloadToastText.isError ? "#5A3030" : "#2D6944"
        z: 10

        Text {
            id: downloadToastText
            property bool isError: false
            anchors.centerIn: parent
            color: "#F5EDD6"
            font.pixelSize: 13
        }

        Timer {
            id: toastTimer
            interval: 3500
            onTriggered: downloadToast.visible = false
        }
    }

    Connections {
        target: messageController
        function onMessageDownloaded(path) {
            downloadToastText.isError = false
            downloadToastText.text = "Saved to: " + path
            downloadToast.visible = true
            toastTimer.restart()
        }
        function onMessageDownloadFailed(reason) {
            downloadToastText.isError = true
            downloadToastText.text = "Download failed: " + reason
            downloadToast.visible = true
            toastTimer.restart()
        }
        function onMessageRevokeSucceeded() {
            downloadToastText.isError = false
            downloadToastText.text = "Delivery revoked from recipient"
            downloadToast.visible = true
            toastTimer.restart()
        }
        function onMessageRevokeFailed() {
            downloadToastText.isError = true
            downloadToastText.text = "Revoke failed — message may already be delivered"
            downloadToast.visible = true
            toastTimer.restart()
        }
    }

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
            id: messageList
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true

            model: conversationController ? conversationController.messages : null
            verticalLayoutDirection: ListView.TopToBottom

            delegate: MessageDelegate {}

            onCountChanged: {
                if (count > 0) {
                    // keep view scrolled to the most recent message (bottom)
                    positionViewAtIndex(count - 1, ListView.End)
                }
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