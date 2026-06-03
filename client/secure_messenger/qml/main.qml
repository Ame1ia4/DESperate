import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "views"

ApplicationWindow {
    id: root
    visible: true
    width: 1400
    height: 900
    color: "#1B3B28"

    title: "Secure Messenger"

    property int authScreenIndex: 0 // 0 login, 1 sign up

    header: ToolBar {
        visible: authController && authController.authenticated
        implicitHeight: 48
        background: Rectangle { color: "#2B6D45" }
        RowLayout {
            anchors.fill: parent
            anchors.margins: 10

            Label {
                text: "Secure Messenger"
                color: "#F5EDD6"
                font.bold: true
                font.pixelSize: 20
            }

            Item {
                Layout.fillWidth: true
            }

            Button {
                text: "Change Password"
                onClicked: {
                    changePassCurrentField.text = ""
                    changePassNewField.text = ""
                    changePassConfirmField.text = ""
                    changePassError.text = ""
                    changePasswordDialog.open()
                }
            }

            Button {
                text: "Logout"
                implicitWidth: 90
                implicitHeight: 32
                onClicked: authController.logout()
                background: Rectangle {
                    color: "#4FAE7C"
                    radius: 16
                }
                contentItem: Text {
                    text: parent.text
                    color: "#1B3B28"
                    font.bold: true
                    font.pixelSize: 13
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
            }
        }
    }

    StackLayout {
        anchors.fill: parent
        currentIndex: authController && authController.authenticated ? 1 : 0

        Item {
            property string statusMessage: ""
            property bool statusIsError: false

            id: authItem

            StackLayout {
                anchors.fill: parent
                currentIndex: root.authScreenIndex

                LoginView {
                    onLoginRequested: function(username, password) {
                        authItem.statusMessage = ""
                        authController.login(username, password)
                    }
                    onOpenSignUpRequested: {
                        authItem.statusMessage = ""
                        root.authScreenIndex = 1
                    }
                }

                SignupView {
                    onSignUpRequested: function(username, password, confirmPassword) {
                        authItem.statusMessage = ""
                        authController.signUp(username, password, confirmPassword)
                    }
                    onBackRequested: {
                        authItem.statusMessage = ""
                        root.authScreenIndex = 0
                    }
                }
            }

            Label {
                anchors.horizontalCenter: parent.horizontalCenter
                anchors.bottom: parent.bottom
                anchors.bottomMargin: 30
                text: authItem.statusMessage
                color: authItem.statusIsError ? "#FF6B6B" : "#7EE8A2"
                visible: text.length > 0
                wrapMode: Text.Wrap
            }

            Connections {
                target: authController

                function onAuthErrorChanged() {
                    if (authController.authError.length > 0) {
                        authItem.statusIsError = true
                        authItem.statusMessage = authController.authError
                    }
                }

                function onRegistrationSucceeded() {
                    authItem.statusIsError = false
                    authItem.statusMessage = "Account created. Please log in."
                    root.authScreenIndex = 0
                }

                function onRegistrationFailed(reason) {
                    authItem.statusIsError = true
                    authItem.statusMessage = reason
                }

                function onLoginFailed(reason) {
                    authItem.statusIsError = true
                    authItem.statusMessage = reason
                }
            }
        }

        SplitView {
            id: mainSplit
            anchors.fill: parent

            ConversationList {
                SplitView.preferredWidth: mainSplit.width * 0.2
                SplitView.minimumWidth: 180
            }

            MessageView {
                SplitView.fillWidth: true
            }
        }
    }

    // Poll for pending messages every 5 seconds while authenticated.
    Timer {
        id: messagePollTimer
        interval: 5000
        repeat: true
        running: authController && authController.authenticated
        onTriggered: messageController.pullAndProcessMessages("")
    }

    Connections {
        target: authController
        function onAuthenticatedChanged() {
            if (authController.authenticated) {
                conversationController.loadConversations()
                messageController.pullAndProcessMessages("")
                root.authScreenIndex = 0
            }
        }
    }

    Dialog {
        id: changePasswordDialog
        title: "Change Password"
        modal: true
        anchors.centerIn: parent

        Column {
            spacing: 12
            width: 300

            TextField {
                id: changePassCurrentField
                width: parent.width
                placeholderText: "Current password"
                echoMode: TextInput.Password
            }

            TextField {
                id: changePassNewField
                width: parent.width
                placeholderText: "New password"
                echoMode: TextInput.Password
            }

            TextField {
                id: changePassConfirmField
                width: parent.width
                placeholderText: "Confirm new password"
                echoMode: TextInput.Password
            }

            Text {
                id: changePassError
                color: "#FF6B6B"
                visible: text.length > 0
                wrapMode: Text.Wrap
                width: parent.width
            }
        }

        footer: DialogButtonBox {
            Button {
                text: "Change"
                DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole
                onClicked: {
                    changePassError.text = ""
                    authController.changePassword(
                        changePassCurrentField.text,
                        changePassNewField.text,
                        changePassConfirmField.text)
                }
            }
            Button {
                text: "Cancel"
                DialogButtonBox.buttonRole: DialogButtonBox.RejectRole
                onClicked: changePasswordDialog.close()
            }
        }

        Connections {
            target: authController
            function onChangePasswordSucceeded() {
                changePasswordDialog.close()
            }
            function onChangePasswordFailed(reason) {
                changePassError.text = reason
            }
        }
    }
}