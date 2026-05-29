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
        visible: authController.authenticated
        background: Rectangle { color: "#2B6D45" }
        RowLayout {
            anchors.fill: parent
            anchors.margins: 8

            Label {
                text: "Secure Messenger"
                color: "#F5EDD6"
                font.bold: true
            }

            Item {
                Layout.fillWidth: true
            }

            Button {
                text: "Logout"
                onClicked: authController.logout()
            }
        }
    }

    StackLayout {
        anchors.fill: parent
        currentIndex: authController.authenticated ? 1 : 0

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
            ConversationList {
                width: 350
            }

            MessageView {
                Layout.fillWidth: true
            }
        }
    }

    Connections {
        target: authController
        function onAuthenticatedChanged() {
            if (authController.authenticated) {
                conversationController.loadConversations()
                root.authScreenIndex = 0
            }
        }
    }
}