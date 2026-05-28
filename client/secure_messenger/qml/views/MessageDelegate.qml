import QtQuick
import QtQuick.Controls

Item {
    id: root

    required property string plaintext
    required property bool outgoing
    required property bool verified

    width: ListView.view.width
    height: bubble.height + 10

    Rectangle {
        id: bubble

        width: parent.width * 0.72
        radius: 18

        anchors {
            right: outgoing ? parent.right : undefined
            left: outgoing ? undefined : parent.left
            margins: 10
        }

        color: outgoing ? "#3C8A5A" : "#2A5B45"

        Text {
            anchors.margins: 14
            anchors.fill: parent
            text: plaintext
            wrapMode: Text.Wrap
            color: "#F8F0D7"
        }
    }
}