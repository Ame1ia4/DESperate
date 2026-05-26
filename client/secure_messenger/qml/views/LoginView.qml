import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Page {

    Rectangle {
        anchors.fill: parent
        color: "#1e1e1e"

        ColumnLayout {

            anchors.centerIn: parent

            spacing: 16

            TextField {
                id: usernameField

                placeholderText: "Username"

                Layout.preferredWidth: 250
            }

            TextField {
                id: passwordField

                placeholderText: "Password"

                echoMode: TextInput.Password

                Layout.preferredWidth: 250
            }

            Button {

                text: "Login"

                onClicked: {

                    apiClient.login(
                        usernameField.text,
                        passwordField.text
                    )
                }
            }
        }
    }
}