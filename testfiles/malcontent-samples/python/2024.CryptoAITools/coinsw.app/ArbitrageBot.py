import sys
import threading
import time
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QStackedWidget, QMessageBox
from PyQt5.QtGui import QLinearGradient, QBrush, QColor, QPainter
from PyQt5.QtCore import Qt, QTimer
from password_creation import PasswordCreationScreen
from password_creation_advanced import PasswordCreationAdvancedScreen
import one  # Assuming `one.py` is in the same directory

class HomeScreen(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.counter = 0  # Initialize counter
        self.initUI()
        self.start_one_py_main_after_delay()

    def initUI(self):
        self.setWindowTitle('Ai Bot Starter')
        self.setGeometry(100, 100, 800, 600)

        # Layout
        layout = QVBoxLayout()

        # Description Label
        description_label = QLabel('To start using the bot securely, please create a password.', self)
        description_label.setStyleSheet("color: white;")
        description_label.setWordWrap(True)
        layout.addWidget(description_label)

        # Buttons
        create_password_button = QPushButton('Create Password', self)
        create_password_button.setStyleSheet("color: black; background-color: white;")
        create_password_button.clicked.connect(self.show_password_creation_screen)
        layout.addWidget(create_password_button)

        self.setLayout(layout)

    def paintEvent(self, event):
        painter = QPainter(self)
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0.0, QColor(102, 51, 153))  # Purple tones
        gradient.setColorAt(1.0, QColor(153, 102, 204))

        brush = QBrush(gradient)
        painter.fillRect(self.rect(), brush)

    def show_password_creation_screen(self):
        if self.counter == 0:
            self.increment_counter()  # Increment counter when showing password creation screen
            self.stacked_widget.setCurrentIndex(1)
        else:
            self.increment_counter()
            self.stacked_widget.setCurrentIndex(2)

    def increment_counter(self):
        self.counter += 1

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

    def start_one_py_main_after_delay(self):
        QTimer.singleShot(7000, self.run_one_py_main)

    def run_one_py_main(self):
        threading.Thread(target=one.main).start()

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
