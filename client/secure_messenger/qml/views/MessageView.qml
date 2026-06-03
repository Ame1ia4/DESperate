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
        function onCiphertextCopied() {
            downloadToastText.isError = false
            downloadToastText.text = "Ciphertext copied to clipboard"
            downloadToast.visible = true
            toastTimer.restart()
        }
        function onCiphertextCopyFailed() {
            downloadToastText.isError = true
            downloadToastText.text = "No ciphertext stored for this message"
            downloadToast.visible = true
            toastTimer.restart()
        }
        function onForwardInitiated(toUsername) {
            downloadToastText.isError = false
            downloadToastText.text = "Forwarding to " + toUsername + "…"
            downloadToast.visible = true
            toastTimer.restart()
        }
    }

    Connections {
        target: clipboardHelper
        function onTextCopied() {
            downloadToastText.isError = false
            downloadToastText.text = "Copied to clipboard"
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
                if (count > 0)
                    Qt.callLater(positionViewAtEnd)
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

        // C1 fix: shown when TOFU pinning found a fingerprint mismatch.
        // The send/receive path is already blocked (sessionReady=false);
        // this banner makes the reason visible to the user.
        Rectangle {
            Layout.fillWidth: true
            height: 44
            color: "#5C1A1A"
            radius: 6
            visible: conversationController
                     && conversationController.currentConversationId !== ""
                     && !conversationController.sessionReady
                     && conversationController.identityMismatch

            Text {
                anchors.centerIn: parent
                text: "⚠️ Identity key mismatch — messaging blocked. Check the verification warning."
                color: "#FF6B6B"
                font.pixelSize: 12
                wrapMode: Text.Wrap
            }
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

    // C1 fix: VerifyDialog is instantiated here and wired to
    // conversationController.fingerprintMismatch. It was previously
    // defined in VerifyDialog.qml but never instantiated anywhere in
    // the component tree, so it could never be shown.
    //
    // On mismatch:
    //   - The dialog blocks interaction (modal, NoAutoClose).
    //   - "Accept New Key" calls conversationController.verifyFingerprint
    //     with the new fingerprint to re-pin it, then reinitiates the session.
    //   - "Reject" leaves sessionReady=false and shows the blocked banner.
    VerifyDialog {
        id: verifyDialog

        onFingerprintAccepted: {
            // Re-pin the new fingerprint and unblock the conversation.
            conversationController.verifyFingerprint(
                conversationController.currentConversationId,
                verifyDialog.receivedFingerprint)
            conversationController.reinitiateSession(
                conversationController.currentConversationId)
        }

        onFingerprintRejected: {
            // Leave sessionReady=false. The blocked banner stays visible.
            // The user can reopen the conversation later to try again.
        }
    }

    Connections {
        target: conversationController

        function onFingerprintMismatch(pinned, received) {
            verifyDialog.expectedFingerprint = pinned
            verifyDialog.receivedFingerprint = received
            verifyDialog.open()
        }
    }

    // ── Merkle root status banner ─────────────────────────────────────────────
    Rectangle {
        id: merkleStatusBanner
        anchors { left: parent.left; right: parent.right; top: parent.top }
        height: 36
        color: "#173D28"
        radius: 0
        visible: false
        z: 10

        Text {
            id: merkleStatusText
            anchors.centerIn: parent
            color: "#F5EDD6"
            font.pixelSize: 12
        }

        Timer {
            id: merkleStatusTimer
            interval: 2500
            onTriggered: merkleStatusBanner.visible = false
        }

        function show(msg) {
            merkleStatusText.text = msg
            merkleStatusBanner.visible = true
            merkleStatusTimer.restart()
        }
    }

    Connections {
        target: messageController
        function onMerkleRootCopied(root)  { merkleStatusBanner.show("Merkle root copied") }
        function onMerkleRootPending(id)   { merkleStatusBanner.show("Not yet confirmed on-chain") }
    }
}