import QtQuick
import QtQuick.Controls

Page {
    Rectangle {
        anchors.fill: parent
        color: "#121212"

        Column {
            anchors.margins: 20
            anchors.fill: parent
            spacing: 16

            Text {
                text: "Security Settings"
                color: "white"
                font.pixelSize: 24
            }

            Switch {
                text: "Enable PQ Hybrid Encryption"
                checked: true
            }

            Switch {
                text: "Strict TOFU Pinning"
                checked: true
            }

            Switch {
                text: "Certificate Pinning"
                checked: true
            }
        }
    }
}