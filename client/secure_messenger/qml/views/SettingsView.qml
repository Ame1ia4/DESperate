import QtQuick
import QtQuick.Controls

// These features are security requirements and are always enforced.
// They are not configurable options.
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

            SecurityRow {
                label: "PQ Hybrid Encryption"
                description: "X25519 + ML-KEM key agreement (PQXDH)"
            }

            SecurityRow {
                label: "TOFU Identity Pinning"
                description: "First-contact fingerprint is pinned and verified on every message"
            }

            SecurityRow {
                label: "TLS 1.3 Certificate Verification"
                description: "Peer certificate is verified against system CA store on every connection"
            }
        }
    }

    component SecurityRow: Column {
        property string label: ""
        property string description: ""

        spacing: 2

        Row {
            spacing: 8

            Rectangle {
                width: 10
                height: 10
                radius: 5
                color: "#4FAE7C"
                anchors.verticalCenter: parent.verticalCenter
            }

            Text {
                text: label
                color: "white"
                font.pixelSize: 15
                font.bold: true
            }
        }

        Text {
            text: description
            color: "#9ABFA8"
            font.pixelSize: 12
            leftPadding: 18
        }
    }
}