import QtQuick
import QtQuick.Controls

Rectangle {
    color: "#1F4F33"

    ListView {
        anchors.fill: parent
        spacing: 10
        clip: true

        model: conversationController ? conversationController.conversations : null

        delegate: Rectangle {
            width: parent.width
            height: 76
            color: verified ? "#305C40" : "#264F3B"
            radius: 12
            border.color: verified ? "#83CAA4" : "#3F7A56"
            border.width: 1

            MouseArea {
                anchors.fill: parent
                onClicked: {
                    conversationController.openConversation(conversationId)
                }
            }

            Column {
                anchors.fill: parent
                anchors.margins: 12

                Text {
                    text: participant
                    color: "#F5EDD6"
                    font.bold: true
                    font.pixelSize: 16
                }

                Text {
                    text: lastMessage
                    color: "#D6E4CA"
                    elide: Text.ElideRight
                }

                Text {
                    text: fingerprint
                    color: "#B3E3B7"
                    font.pixelSize: 10
                }
            }
        }
    }
}