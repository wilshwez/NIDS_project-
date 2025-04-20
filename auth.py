import sys
import sqlite3
from PyQt6.QtWidgets import QInputDialog
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout,
    QMessageBox, QComboBox, QFormLayout, QHBoxLayout
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt
from hashlib import sha256
from admin_panel import AdminPanel  # Import the admin panel

DB_FILE = "nids_auth.db"
MAX_LOGIN_ATTEMPTS = 3
login_attempts = {}

# Initialize the database
def initialize_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            security_question TEXT NOT NULL,
            security_answer TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    add_admin()  # Ensure an admin exists

# Ensure admin exists
def add_admin():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    admin_username = "harzad"
    admin_password = hash_password("harzad12")
    cursor.execute("SELECT * FROM users WHERE username=?", (admin_username,))
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password, email, role, security_question, security_answer) VALUES (?, ?, ?, ?, ?, ?)",
            (admin_username, admin_password, "harzad@gmail.com", "admin", "Your first pet's name?", hash_password("adminpet"))
        )
        conn.commit()
    conn.close()

# Password hashing with salt
def hash_password(password):
    salt = "nids_secure_salt"
    return sha256((password + salt).encode()).hexdigest()

# Login function for handling admin panel access
def login(username, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password, role FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and user[0] == hash_password(password):
        print("✅ Login successful!")
        if user[1].lower() == "admin":
            app = QApplication(sys.argv)
            admin_window = AdminPanel(username)
            admin_window.show()
            sys.exit(app.exec())
        else:
            print("🔒 You are logged in as a regular user.")
    else:
        print("❌ Invalid username or password.")

class AuthSystem(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔒 NIDS - Secure Login System")
        self.setGeometry(500, 200, 420, 350)  # Increased height for new button
        self.setStyleSheet("""
            background-color: #F0F0F0;
            QPushButton {
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #E0E0E0;
            }
            QPushButton#forgotButton {
                color: #0066CC;
                text-decoration: underline;
                border: none;
                background: transparent;
            }
        """)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        title_label = QLabel("👨‍💻 Network Intrusion Detection System")
        title_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        form_layout = QFormLayout()
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter Username")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.role_selection = QComboBox()
        self.role_selection.addItems(["User"])  # Only user role selectable
        
        form_layout.addRow(QLabel("👤 Username:"), self.username_input)
        form_layout.addRow(QLabel("🔑 Password:"), self.password_input)
        form_layout.addRow(QLabel("⚡ Role:"), self.role_selection)
        
        # Forgot password button
        self.forgot_button = QPushButton("Forgot Password?")
        self.forgot_button.setObjectName("forgotButton")
        self.forgot_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.forgot_button.clicked.connect(self.handle_forgot_password)
        
        # Login and Sign Up buttons
        self.login_button = QPushButton("🔓 Login")
        self.login_button.setStyleSheet("background-color: #4CAF50; color: white;")
        self.login_button.clicked.connect(self.login)
        
        self.signup_button = QPushButton("📝 Sign Up")
        self.signup_button.setStyleSheet("background-color: #2196F3; color: white;")
        self.signup_button.clicked.connect(self.open_signup_window)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.signup_button)
        
        layout.addWidget(title_label)
        layout.addLayout(form_layout)
        layout.addWidget(self.forgot_button, alignment=Qt.AlignmentFlag.AlignRight)
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def handle_forgot_password(self):
        """Handle password reset request from login screen"""
        username, ok = QInputDialog.getText(
            self,
            "Forgot Password",
            "Enter your username:",
            QLineEdit.EchoMode.Normal,
            ""
        )
        
        if not ok or not username.strip():
            return
            
        try:
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT security_question, security_answer FROM users WHERE username=?",
                    (username.strip(),)
                )
                result = cursor.fetchone()
                
                if not result:
                    QMessageBox.warning(self, "Not Found", "Username not found in system.")
                    return
                    
                security_question, security_answer_hash = result
                
                # Verify security answer
                answer, ok = QInputDialog.getText(
                    self,
                    "Security Question",
                    f"{security_question}\n\nEnter your answer:",
                    QLineEdit.EchoMode.Normal,
                    ""
                )
                
                if not ok or not answer.strip():
                    return
                
                # Hash the provided answer and compare
                hashed_answer = sha256((answer.lower() + "nids_secure_salt").encode()).hexdigest()
                
                if hashed_answer == security_answer_hash:
                    # Get new password
                    new_password, ok = QInputDialog.getText(
                        self,
                        "New Password",
                        "Enter your new password (min 8 characters):",
                        QLineEdit.EchoMode.Password,
                        ""
                    )
                    
                    if ok and new_password.strip() and len(new_password) >= 8:
                        # Update password in database
                        hashed_password = sha256((new_password + "nids_secure_salt").encode()).hexdigest()
                        cursor.execute(
                            "UPDATE users SET password=? WHERE username=?",
                            (hashed_password, username)
                        )
                        conn.commit()
                        
                        QMessageBox.information(
                            self,
                            "Success",
                            "Your password has been reset successfully!\n\n"
                            "You can now login with your new password."
                        )
                    else:
                        QMessageBox.warning(self, "Error", "Password must be at least 8 characters long.")
                else:
                    QMessageBox.warning(self, "Error", "Incorrect security answer.")
        except sqlite3.Error as e:
            QMessageBox.critical(self, "Error", f"Database error: {str(e)}")
    
    def login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        if username in login_attempts and login_attempts[username] >= MAX_LOGIN_ATTEMPTS:
            QMessageBox.critical(self, "⛔ Account Locked", "Too many failed login attempts!")
            return
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT password, role FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and user[0] == hash_password(password):
            login_attempts[username] = 0
            QMessageBox.information(self, "✅ Access Granted", f"Welcome, {user[1].capitalize()}!")
            if user[1].lower() == "admin":
                self.open_admin_panel(username)
            self.close()
        else:
            login_attempts[username] = login_attempts.get(username, 0) + 1
            QMessageBox.critical(self, "⛔ Login Failed", "Invalid username or password!")
    
    def open_admin_panel(self, username):
        self.admin_window = AdminPanel(username)
        self.admin_window.show()

    def open_signup_window(self):
        self.signup_window = SignUpWindow()
        self.signup_window.show()

class SignUpWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("📝 Create an Account")
        self.setGeometry(500, 250, 420, 380)
        self.setStyleSheet("""
            QPushButton {
                padding: 5px;
                background-color: #4CAF50;
                color: white;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        form_layout = QFormLayout()
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter Username")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter Email")
        self.role_selection = QComboBox()
        self.role_selection.addItems(["User"])  # Users cannot self-register as admin
        self.security_question_input = QLineEdit()
        self.security_question_input.setPlaceholderText("Enter Security Question")
        self.security_answer_input = QLineEdit()
        self.security_answer_input.setPlaceholderText("Enter Security Answer")
        
        form_layout.addRow("👤 Username:", self.username_input)
        form_layout.addRow("🔑 Password:", self.password_input)
        form_layout.addRow("📧 Email:", self.email_input)
        form_layout.addRow("❓ Security Question:", self.security_question_input)
        form_layout.addRow("🔑 Security Answer:", self.security_answer_input)
        
        self.signup_button = QPushButton("✅ Register")
        self.signup_button.clicked.connect(self.signup)
        
        layout.addLayout(form_layout)
        layout.addWidget(self.signup_button)
        self.setLayout(layout)

    def signup(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        email = self.email_input.text().strip()
        role = "user"  # Force role to user
        security_question = self.security_question_input.text().strip()
        security_answer = self.security_answer_input.text().strip()
        
        if not username or not password or not email or not security_question or not security_answer:
            QMessageBox.warning(self, "⚠ Error", "All fields are required!")
            return
        
        if len(password) < 8:
            QMessageBox.warning(self, "⚠ Error", "Password must be at least 8 characters long!")
            return
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password, email, role, security_question, security_answer) VALUES (?, ?, ?, ?, ?, ?)",
                (username, hash_password(password), email, role, security_question, hash_password(security_answer))
            )
            conn.commit()
            QMessageBox.information(self, "🎉 Success", "Account Created! You can now login.")
            self.close()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "⚠ Error", "Username already exists!")
        finally:
            conn.close()

if __name__ == "__main__":
    initialize_db()
    app = QApplication(sys.argv)
    auth_window = AuthSystem()
    auth_window.show()
    sys.exit(app.exec())