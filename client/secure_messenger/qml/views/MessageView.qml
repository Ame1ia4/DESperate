import QtQuick
import QtQuick.Controls

Page {

    Rectangle {
        anchors.fill: parent
        color: "#121212"

        ListView {
            anchors.fill: parent

            model: messageModel

            delegate: Rectangle {

                width: parent.width
                height: 80

                color: "#1E1E1E"

                Text {
                    text: content

                    color: "white"

                    anchors.centerIn: parent
                }
            }
        }
    }
}