import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Page {
    property bool showPassword: false
    signal signUpRequested(string username, string password, string confirmPassword)
    signal backRequested()

    function passwordError(pw) {
        if (pw.length === 0)          return ""
        if (pw.length < 12)           return "Password must be at least 12 characters"
        if (!/[A-Za-z]/.test(pw))     return "Password must contain at least one letter"
        if (!/[0-9]/.test(pw))        return "Password must contain at least one number"
        return ""
    }

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
                placeholderText: "Password (min. 12 chars, letters & numbers)"
                placeholderTextColor: "#C9D4C5"
                maximumLength: 64
                echoMode: showPassword ? TextInput.Normal : TextInput.Password
                background: Rectangle {
                    color: "#2E6D47"
                    radius: 10
                    border.color: passwordError(passwordField.text) !== "" ? "#FF6B6B" : "#4FAE7C"
                    border.width: 1
                }
                color: "#F5EDD6"
            }

            Text {
                visible: passwordError(passwordField.text) !== ""
                text: passwordError(passwordField.text)
                color: "#FF6B6B"
                font.pixelSize: 12
                Layout.topMargin: -10
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
                enabled: passwordError(passwordField.text) === ""  && passwordField.text.length > 0
                background: Rectangle {
                    color: parent.enabled ? "#4FAE7C" : "#3A5A47"
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
