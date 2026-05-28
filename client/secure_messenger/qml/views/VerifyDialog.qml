import QtQuick
import QtQuick.Controls

Dialog {
    id: verifyDialog

    property string expectedFingerprint
    property string receivedFingerprint

    title: "Identity Warning"
    modal: true

    Column {
        spacing: 12

        Text {
            text: "Pinned identity differs from received identity"
        }

        Text {
            text: "Expected: " + expectedFingerprint
        }

        Text {
            text: "Received: " + receivedFingerprint
        }

        Button {
            text: "Reject"
            onClicked: verifyDialog.close()
        }
    }
}