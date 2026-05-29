import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Page {
    property bool showPassword: false
    signal signUpRequested(string username, string password, string confirmPassword)
    signal backRequested()

    Rectangle {
        anchors.fill: parent
        color: "#214D2D"

        ColumnLayout {
            anchors.centerIn: parent
            width: 360
            spacing: 18

            Text {
                text: "Create Account"
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

            TextField {
                id: confirmPasswordField
                placeholderText: "Confirm Password"
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
                onCheckedChanged: {
                    passwordField.echoMode = checked ? TextInput.Normal : TextInput.Password
                    confirmPasswordField.echoMode = checked ? TextInput.Normal : TextInput.Password
                }
            }

            Button {
                text: "Sign Up"
                background: Rectangle {
                    color: "#4FAE7C"
                    radius: 10
                }
                onClicked: {
                    signUpRequested(
                        usernameField.text,
                        passwordField.text,
                        confirmPasswordField.text)
                }
            }

            Button {
                text: "Back to Login"
                flat: true
                onClicked: backRequested()
            }
        }
    }
}
