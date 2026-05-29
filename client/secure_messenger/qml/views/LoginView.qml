import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Page {
    property bool showPassword: false
    signal loginRequested(string username, string password)
    signal openSignUpRequested()

    Rectangle {
        anchors.fill: parent
        color: "#214D2D"

        ColumnLayout {
            anchors.centerIn: parent
            width: 360
            spacing: 18

            Text {
                text: "Secure Messenger Login"
                color: "#F5EDD6"
                font.pixelSize: 28
                font.bold: true
            }

            TextField {
                id: usernameField
                placeholderText: "Username"
                placeholderTextColor: "#C9D4C5"
                background: Rectangle {
                    color: "#2E6D47"
                    radius: 10
                    border.color: "#4FAE7C"
                    border.width: 1
                }
                color: "#F5EDD6"
            }

            TextField {
                id: passwordField
                placeholderText: "Password"
                placeholderTextColor: "#C9D4C5"
                maximumLength: 64
                echoMode: showPassword ? TextInput.Normal : TextInput.Password
                background: Rectangle {
                    color: "#2E6D47"
                    radius: 10
                    border.color: "#4FAE7C"
                    border.width: 1
                }
                color: "#F5EDD6"
            }

            CheckBox {
                id: showPasswordToggle
                text: "Show password"
                checked: false
                contentItem: Text {
                    text: showPasswordToggle.text
                    color: "#F5EDD6"
                    leftPadding: showPasswordToggle.indicator
                                     ? showPasswordToggle.indicator.width + showPasswordToggle.spacing
                                     : 0
                    verticalAlignment: Text.AlignVCenter
                }
                onCheckedChanged: passwordField.echoMode = checked ? TextInput.Normal : TextInput.Password
            }

            Button {
                text: "Login"
                background: Rectangle {
                    color: "#4FAE7C"
                    radius: 10
                }
                onClicked: {
                    loginRequested(
                        usernameField.text,
                        passwordField.text)
                }
            }

            Button {
                text: "No account? Sign up"
                flat: true
                font.pixelSize: 14
                onClicked: openSignUpRequested()
            }
        }
    }
}