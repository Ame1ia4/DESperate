import QtQuick
import QtQuick.Controls

// Shown when TrustStore.fingerprintMismatch fires.
//
// expectedFingerprint — the fingerprint pinned at first contact (TOFU).
//                       Stored locally; the server never supplied it.
// receivedFingerprint — the fingerprint the server is asserting right now
//                       for this identity.
//
// A mismatch means either:
//   (a) the contact regenerated their keys (e.g. reinstalled), OR
//   (b) a server-side key-swap / MITM attack.
//
// The user must decide. "Accept New Key" re-pins and trusts the new
// fingerprint. "Reject" blocks the conversation until resolved.
Dialog {
    id: verifyDialog

    property string expectedFingerprint: ""
    property string receivedFingerprint: ""

    signal fingerprintAccepted()
    signal fingerprintRejected()

    title: "Identity Verification Warning"
    modal: true
    closePolicy: Popup.NoAutoClose

    Column {
        spacing: 12
        width: 420

        Text {
            width: parent.width
            wrapMode: Text.Wrap
            text: "The identity key for this contact has changed since you first connected. " +
                  "This may mean the contact reinstalled the app, or it may indicate a man-in-the-middle attack. " +
                  "Verify the fingerprint out-of-band before accepting."
            color: "#F5EDD6"
        }

        Text {
            text: "Pinned (trusted):  " + expectedFingerprint
            color: "#7EE8A2"
            font.family: "Courier"
        }

        Text {
            text: "Received (new):    " + receivedFingerprint
            color: "#FF6B6B"
            font.family: "Courier"
        }

        Row {
            spacing: 12

            Button {
                text: "Accept New Key"
                onClicked: {
                    verifyDialog.fingerprintAccepted()
                    verifyDialog.close()
                }
            }

            Button {
                text: "Reject"
                onClicked: {
                    verifyDialog.fingerprintRejected()
                    verifyDialog.close()
                }
            }
        }
    }
}