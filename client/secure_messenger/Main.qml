import QtQuick
import QtQuick.Controls

ApplicationWindow {

    width: 1200
    height: 800

    visible: true

    title: "Secure Messenger"

    StackView {
        id: stackView

        anchors.fill: parent

        initialItem: LoginView {}
    }
}