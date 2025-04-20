import sys
import sqlite3
from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QTextEdit, QMessageBox, QLineEdit, QLabel, QComboBox, 
    QDateEdit, QFileDialog, QDialog, QFormLayout, QHBoxLayout, QCheckBox, QProgressBar
)
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import QDate, Qt
import random
import string
from hashlib import sha256
import datetime
import re

DB_FILE = "nids_auth.db"

class PasswordResetDialog(QDialog):
    def __init__(self, username, security_question, parent=None):
        super().__init__(parent)
        self.username = username
        self.security_question = security_question
        self.setWindowTitle(f"🔑 Reset Password for {username}")
        self.setMinimumWidth(400)
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Security question section
        security_label = QLabel(f"Security Question: {self.security_question}")
        security_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        layout.addWidget(security_label)
        
        form_layout = QFormLayout()
        self.answer_input = QLineEdit()
        self.answer_input.setPlaceholderText("Enter your security answer")
        form_layout.addRow("Security Answer:", self.answer_input)
        layout.addLayout(form_layout)
        
        # Password generation options
        options_label = QLabel("Password Options:")
        options_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        layout.addWidget(options_label)
        
        # Password length
        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Password Length:"))
        self.length_combo = QComboBox()
        self.length_combo.addItems(["8", "10", "12", "16", "20"])
        self.length_combo.setCurrentIndex(1)  # Default to 10 characters
        self.length_combo.currentIndexChanged.connect(self.update_password_preview)
        length_layout.addWidget(self.length_combo)
        layout.addLayout(length_layout)
        
        # Character options
        options_layout = QVBoxLayout()
        self.include_uppercase = QCheckBox("Include Uppercase Letters (A-Z)")
        self.include_uppercase.setChecked(True)
        self.include_uppercase.stateChanged.connect(self.update_password_preview)
        
        self.include_lowercase = QCheckBox("Include Lowercase Letters (a-z)")
        self.include_lowercase.setChecked(True)
        self.include_lowercase.stateChanged.connect(self.update_password_preview)
        
        self.include_numbers = QCheckBox("Include Numbers (0-9)")
        self.include_numbers.setChecked(True)
        self.include_numbers.stateChanged.connect(self.update_password_preview)
        
        self.include_special = QCheckBox("Include Special Characters (!@#$%^&*)")
        self.include_special.setChecked(False)
        self.include_special.stateChanged.connect(self.update_password_preview)
        
        options_layout.addWidget(self.include_uppercase)
        options_layout.addWidget(self.include_lowercase)
        options_layout.addWidget(self.include_numbers)
        options_layout.addWidget(self.include_special)
        layout.addLayout(options_layout)
        
        # Password preview
        preview_layout = QVBoxLayout()
        preview_label = QLabel("Password Preview:")
        self.password_preview = QLineEdit()
        self.password_preview.setReadOnly(True)
        self.password_preview.setPlaceholderText("Generated password will appear here")
        
        # Generate button
        self.generate_btn = QPushButton("🔄 Generate New Password")
        self.generate_btn.clicked.connect(self.generate_password)
        
        preview_layout.addWidget(preview_label)
        preview_layout.addWidget(self.password_preview)
        preview_layout.addWidget(self.generate_btn)
        layout.addLayout(preview_layout)
        
        # Password strength meter
        strength_layout = QHBoxLayout()
        strength_layout.addWidget(QLabel("Password Strength:"))
        self.strength_meter = QProgressBar()
        self.strength_meter.setRange(0, 100)
        self.strength_meter.setValue(0)
        strength_layout.addWidget(self.strength_meter)
        layout.addLayout(strength_layout)
        
        # Manual password option
        manual_layout = QHBoxLayout()
        self.manual_password = QLineEdit()
        self.manual_password.setPlaceholderText("Or enter password manually")
        self.manual_password.textChanged.connect(self.check_manual_password)
        manual_layout.addWidget(self.manual_password)
        layout.addLayout(manual_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.reset_btn = QPushButton("✅ Reset Password")
        self.reset_btn.clicked.connect(self.accept)
        self.reset_btn.setEnabled(False)  # Disabled until valid password
        
        self.cancel_btn = QPushButton("❌ Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(self.reset_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Generate initial password
        self.generate_password()
        
    def generate_password(self):
        """Generate a random password based on selected options"""
        length = int(self.length_combo.currentText())
        char_sets = []
        
        if self.include_uppercase.isChecked():
            char_sets.append(string.ascii_uppercase)
        if self.include_lowercase.isChecked():
            char_sets.append(string.ascii_lowercase)
        if self.include_numbers.isChecked():
            char_sets.append(string.digits)
        if self.include_special.isChecked():
            char_sets.append("!@#$%^&*()-_=+[]{}|;:,.<>?")
            
        # Ensure at least one character set is selected
        if not char_sets:
            char_sets.append(string.ascii_lowercase)
            self.include_lowercase.setChecked(True)
            
        # Combine all character sets
        all_chars = ''.join(char_sets)
        
        # Generate password
        password = ''.join(random.choice(all_chars) for _ in range(length))
        
        # Ensure password has at least one character from each selected set
        if length >= len(char_sets):
            password_list = list(password)
            for i, char_set in enumerate(char_sets):
                password_list[i] = random.choice(char_set)
            random.shuffle(password_list)
            password = ''.join(password_list)
            
        self.password_preview.setText(password)
        self.manual_password.clear()
        self.calculate_password_strength(password)
        self.reset_btn.setEnabled(True)
        
    def update_password_preview(self):
        """Update password preview when options change"""
        self.generate_password()
        
    def check_manual_password(self, text):
        """Check strength of manually entered password"""
        if text:
            self.password_preview.clear()
            self.calculate_password_strength(text)
            self.reset_btn.setEnabled(len(text) >= 8)
        else:
            self.reset_btn.setEnabled(self.password_preview.text() != "")
            
    def calculate_password_strength(self, password):
        """Calculate and display password strength"""
        strength = 0
        
        # Length check
        if len(password) >= 8:
            strength += 20
        if len(password) >= 12:
            strength += 10
        if len(password) >= 16:
            strength += 10
            
        # Character variety
        if re.search(r'[A-Z]', password):
            strength += 15
        if re.search(r'[a-z]', password):
            strength += 15
        if re.search(r'[0-9]', password):
            strength += 15
        if re.search(r'[^A-Za-z0-9]', password):
            strength += 15
            
        # Set progress bar value and color
        self.strength_meter.setValue(strength)
        
        if strength < 40:
            self.strength_meter.setStyleSheet("QProgressBar::chunk { background-color: red; }")
        elif strength < 70:
            self.strength_meter.setStyleSheet("QProgressBar::chunk { background-color: orange; }")
        else:
            self.strength_meter.setStyleSheet("QProgressBar::chunk { background-color: green; }")
            
    def get_password(self):
        """Return the selected password"""
        if self.manual_password.text():
            return self.manual_password.text()
        return self.password_preview.text()


class AdminPanel(QWidget):
    def __init__(self, username):  # Accept username as a parameter
        super().__init__()
        self.username = username
        self.setWindowTitle(f"🛠 Admin Panel - {username}")
        self.setGeometry(500, 200, 600, 550)
        self.setStyleSheet("background-color: #F5F5F5; padding: 10px;")
        
        layout = QVBoxLayout()
        
        # Title
        self.title_label = QLabel("🔍 Admin Dashboard")
        self.title_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.title_label)
        
        layout.addSpacing(10)
        # --- Log Management Section ---
        self.view_logs_btn = QPushButton("📜 View Login Logs")
        self.view_logs_btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 5px;")
        self.view_logs_btn.clicked.connect(self.view_logs)
        layout.addWidget(self.view_logs_btn)
        
        self.logs_display = QTextEdit()
        self.logs_display.setReadOnly(True)
        layout.addWidget(self.logs_display)
        
        self.export_logs_btn = QPushButton("💾 Export Logs")
        self.export_logs_btn.setStyleSheet("background-color: #3F51B5; color: white; padding: 5px;")
        self.export_logs_btn.clicked.connect(self.export_logs)
        layout.addWidget(self.export_logs_btn)
        
        self.clear_logs_btn = QPushButton("🗑 Clear Logs")
        self.clear_logs_btn.setStyleSheet("background-color: #F44336; color: white; padding: 5px;")
        self.clear_logs_btn.clicked.connect(self.clear_logs)
        layout.addWidget(self.clear_logs_btn)
        
        layout.addSpacing(10)
        # --- User Management Section ---
        self.user_label = QLabel("👤 Manage Users:")
        layout.addWidget(self.user_label)
        
        self.view_users_btn = QPushButton("📋 View All Users")
        self.view_users_btn.setStyleSheet("background-color: #9C27B0; color: white; padding: 5px;")
        self.view_users_btn.clicked.connect(self.view_users)
        layout.addWidget(self.view_users_btn)
        
        self.delete_user_input = QLineEdit()
        self.delete_user_input.setPlaceholderText("Enter username to delete")
        layout.addWidget(self.delete_user_input)
        
        self.delete_user_btn = QPushButton("❌ Remove User")
        self.delete_user_btn.setStyleSheet("background-color: #FF9800; color: white; padding: 5px;")
        self.delete_user_btn.clicked.connect(self.delete_user)
        layout.addWidget(self.delete_user_btn)
        
        self.reset_user_input = QLineEdit()
        self.reset_user_input.setPlaceholderText("Enter username to reset password")
        layout.addWidget(self.reset_user_input)
        
        self.reset_password_btn = QPushButton("🔑 Reset Password")
        self.reset_password_btn.setStyleSheet("background-color: #607D8B; color: white; padding: 5px;")
        self.reset_password_btn.clicked.connect(self.reset_password)
        layout.addWidget(self.reset_password_btn)
        
        # --- Role Management Section ---
        self.role_user_input = QLineEdit()
        self.role_user_input.setPlaceholderText("Enter username to change role")
        layout.addWidget(self.role_user_input)
        
        self.role_selection = QComboBox()
        self.role_selection.addItems(["Admin", "User", "Moderator"])
        layout.addWidget(self.role_selection)
        
        self.change_role_btn = QPushButton("🔄 Change Role")
        self.change_role_btn.setStyleSheet("background-color: #2196F3; color: white; padding: 5px;")
        self.change_role_btn.clicked.connect(self.change_role)
        layout.addWidget(self.change_role_btn)
        
        self.setLayout(layout)
    
    def view_logs(self):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT username, timestamp FROM login_logs ORDER BY id DESC")
        logs = cursor.fetchall()
        conn.close()
        if logs:
            log_text = "\n".join([f"{log[1]} - {log[0]}" for log in logs])
        else:
            log_text = "No login logs found."
        self.logs_display.setText(log_text)
    
    def export_logs(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Export Logs", "", "Text Files (*.txt);;All Files (*)")
        if file_name:
            try:
                with open(file_name, "w") as file:
                    file.write(self.logs_display.toPlainText())
                QMessageBox.information(self, "✅ Success", "Logs exported successfully!")
            except Exception as e:
                QMessageBox.critical(self, "⛔ Error", f"Failed to export logs: {str(e)}")
    
    def clear_logs(self):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM login_logs")
        conn.commit()
        conn.close()
        self.logs_display.clear()
        QMessageBox.information(self, "✅ Success", "Logs cleared successfully!")
    
    def view_users(self):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT username, role, email FROM users ORDER BY username")
        users = cursor.fetchall()
        conn.close()
        if users:
            user_text = "\n".join([f"👤 {u[0]} | Role: {u[1]} | Email: {u[2]}" for u in users])
        else:
            user_text = "No registered users found."
        QMessageBox.information(self, "📋 User List", user_text)
    
    def delete_user(self):
        username = self.delete_user_input.text().strip()
        if not username:
            QMessageBox.warning(self, "⚠ Error", "Please enter a username to delete.")
            return
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        if not user:
            QMessageBox.warning(self, "⚠ Error", "User not found.")
        elif user[0].lower() == "admin":
            QMessageBox.warning(self, "⚠ Error", "Cannot delete an admin account.")
        else:
            confirm = QMessageBox.question(
                self, "❌ Confirm Deletion",
                f"Are you sure you want to delete '{username}'?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if confirm == QMessageBox.StandardButton.Yes:
                cursor.execute("DELETE FROM users WHERE username=?", (username,))
                conn.commit()
                QMessageBox.information(self, "✅ Success", f"User '{username}' has been deleted.")
        conn.close()
        self.delete_user_input.clear()
    
    # Enhanced reset_password function
    def reset_password(self):
        username = self.reset_user_input.text().strip()
        if not username:
            QMessageBox.warning(self, "⚠ Error", "Enter a username to reset password.")
            return
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT security_question, security_answer FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        
        if not user:
            QMessageBox.warning(self, "⚠ Error", f"User '{username}' not found.")
            conn.close()
            return
            
        # Create and show the password reset dialog
        reset_dialog = PasswordResetDialog(username, user[0], self)
        if reset_dialog.exec():
            # User clicked Reset Password
            answer = reset_dialog.answer_input.text().strip()
            if not answer:
                QMessageBox.warning(self, "⚠ Error", "Security answer is required.")
                conn.close()
                return
                
            # Hash the provided answer to compare with stored hash
            hashed_answer = sha256((answer + "nids_secure_salt").encode()).hexdigest()
            
            if hashed_answer == user[1]:  # Compare with stored hashed answer
                # Get the new password from the dialog
                new_password = reset_dialog.get_password()
                
                # Hash the new password before storing
                hashed_password = sha256((new_password + "nids_secure_salt").encode()).hexdigest()
                
                # Update the password in the database
                cursor.execute("UPDATE users SET password=? WHERE username=?", (hashed_password, username))
                
                # Log the password reset
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute(
                    "INSERT INTO login_logs (username, timestamp) VALUES (?, ?)",
                    (f"Password reset for {username} by {self.username}", timestamp)
                )
                
                conn.commit()
                
                # Show success message with password details
                details = (
                    f"New password for '{username}':\n\n"
                    f"{new_password}\n\n"
                    f"Password strength: {reset_dialog.strength_meter.value()}%\n"
                    f"Please inform the user to change this password after logging in."
                )
                QMessageBox.information(self, "✅ Password Reset", details)
            else:
                QMessageBox.warning(self, "⚠ Error", "Incorrect security answer.")
        
        conn.close()
        self.reset_user_input.clear()
    
    def change_role(self):
        username = self.role_user_input.text().strip()
        new_role = self.role_selection.currentText()
        if not username:
            QMessageBox.warning(self, "⚠ Error", "Please enter a username to change role.")
            return
            
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT role FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        
        if not user:
            QMessageBox.warning(self, "⚠ Error", f"User '{username}' not found.")
            conn.close()
            return
            
        # Prevent removing the last admin
        if user[0].lower() == "admin" and new_role.lower() != "admin":
            cursor.execute("SELECT COUNT(*) FROM users WHERE role=?", ("admin",))
            admin_count = cursor.fetchone()[0]
            
            if admin_count <= 1:
                QMessageBox.warning(self, "⚠ Error", "Cannot change role: This is the last admin account.")
                conn.close()
                return
        
        # Update the role
        cursor.execute("UPDATE users SET role=? WHERE username=?", (new_role, username))
        
        # Log the role change
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO login_logs (username, timestamp) VALUES (?, ?)",
            (f"Role changed for {username} to {new_role} by {self.username}", timestamp)
        )
        
        conn.commit()
        conn.close()
        
        QMessageBox.information(self, "✅ Success", f"Role for '{username}' updated to '{new_role}'.")
        self.role_user_input.clear()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    # For testing purposes, open admin panel as a default admin.
    window = AdminPanel("admin")
    window.show()
    sys.exit(app.exec())

