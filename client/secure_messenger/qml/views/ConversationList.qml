import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    color: "#1F4F33"

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // New chat bar
        Rectangle {
            Layout.fillWidth: true
            height: 56
            color: "#173D28"

            RowLayout {
                anchors.fill: parent
                anchors.margins: 8
                spacing: 6

                TextField {
                    id: newChatField
                    Layout.fillWidth: true
                    placeholderText: "Username…"
                    placeholderTextColor: "#8AB89A"
                    color: "#F5EDD6"
                    font.pixelSize: 13
                    background: Rectangle {
                        color: "#2D6944"
                        radius: 8
                        border.color: newChatField.activeFocus ? "#4FAE7C" : "#3F7A56"
                        border.width: 1
                    }
                    leftPadding: 8
                    rightPadding: 8

                    Keys.onReturnPressed: startChat()
                    Keys.onEnterPressed: startChat()
                }

                Button {
                    text: "+"
                    font.pixelSize: 18
                    font.bold: true
                    implicitWidth: 36
                    implicitHeight: 36
                    background: Rectangle {
                        color: "#4FAE7C"
                        radius: 8
                    }
                    contentItem: Text {
                        text: parent.text
                        color: "#1B3B28"
                        font: parent.font
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                    onClicked: startChat()
                }
            }
        }

        // Error label shown briefly when createChat fails
        Text {
            id: errorLabel
            Layout.fillWidth: true
            Layout.leftMargin: 8
            Layout.rightMargin: 8
            text: ""
            color: "#FF6B6B"
            font.pixelSize: 11
            wrapMode: Text.Wrap
            visible: text.length > 0
        }

        ListView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 8
            clip: true
            topMargin: 8
            bottomMargin: 8
            leftMargin: 8
            rightMargin: 8

            id: convList
            model: conversationController ? conversationController.conversations : null
            verticalLayoutDirection: ListView.TopToBottom

            onCountChanged: {
                if (count > 0) {
                    positionViewAtIndex(count - 1, ListView.End)
                }
            }

            delegate: Rectangle {
                width: ListView.view.width - 16
                height: 72
                color: verified ? "#305C40" : "#264F3B"
                radius: 12
                border.color: verified ? "#83CAA4" : "#3F7A56"
                border.width: 1

                MouseArea {
                    anchors.fill: parent
                    onClicked: conversationController.openConversation(conversationId)
                }

                Column {
                    anchors.fill: parent
                    anchors.margins: 10
                    spacing: 2

                    Text {
                        text: participant
                        color: "#F5EDD6"
                        font.bold: true
                        font.pixelSize: 14
                        elide: Text.ElideRight
                        width: parent.width
                    }

                    Text {
                        text: lastMessage
                        color: "#D6E4CA"
                        font.pixelSize: 12
                        elide: Text.ElideRight
                        width: parent.width
                    }

                    Text {
                        text: fingerprint ? fingerprint.substring(0, 16) + "…" : ""
                        color: "#B3E3B7"
                        font.pixelSize: 10
                        elide: Text.ElideRight
                        width: parent.width
                    }
                }
            }
        }
    }

    function startChat() {
        const username = newChatField.text.trim()
        if (username.length === 0) return
        errorLabel.text = ""
        conversationController.createChat(username)
        newChatField.clear()
    }

    Connections {
        target: conversationController

        function onCreateChatFailed(reason) {
            errorLabel.text = reason
            errorTimer.restart()
        }
    }

    Timer {
        id: errorTimer
        interval: 4000
        onTriggered: errorLabel.text = ""
    }
}
