import sys
import codecs
sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())

import json
import os
import hashlib
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import HMAC, SHA256
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, QPushButton,
                             QVBoxLayout, QFormLayout, QMessageBox, QHBoxLayout, QListWidget, QInputDialog)
import pyperclip  # For working with the clipboard

# Import nového okna
from currency_converter import CurrencyConverter

CONFIG_FILE = "config.json"  # File for storing trade field configuration

# Function to generate a key from a password
def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

# Function to load configuration
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {"fields": []}

# Function to save configuration
def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

# Function to encrypt trade data
def encrypt_store(store_data: dict, password: str) -> str:
    data_json = json.dumps(store_data)
    salt = os.urandom(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(data_json.encode(), AES.block_size))

    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(iv + encrypted_data)
    signature = hmac.digest()

    return base64.b64encode(salt + iv + encrypted_data + signature).decode()

# Function to decrypt trade data
def decrypt_store(token: str, password: str) -> dict:
    raw_data = base64.b64decode(token)
    salt = raw_data[:16]
    iv = raw_data[16:32]
    encrypted_data = raw_data[32:-32]
    signature = raw_data[-32:]

    key = derive_key(password, salt)
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(iv + encrypted_data)
    hmac.verify(signature)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return json.loads(decrypted_data.decode())

# Window for editing fields
class ConfigEditor(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.setWindowTitle("Trade Field Settings")
        self.layout = QVBoxLayout()
        self.field_list = QListWidget()
        self.config = load_config()

        self.load_fields()
        self.layout.addWidget(self.field_list)

        self.add_button = QPushButton("Add Field")
        self.add_button.clicked.connect(self.add_field)
        self.layout.addWidget(self.add_button)

        self.remove_button = QPushButton("Remove Selected Field")
        self.remove_button.clicked.connect(self.remove_field)
        self.layout.addWidget(self.remove_button)

        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_config)
        self.layout.addWidget(self.save_button)

        self.setLayout(self.layout)

    def load_fields(self):
        self.field_list.clear()
        for field in self.config["fields"]:
            self.field_list.addItem(field)

    def add_field(self):
        field, ok = QInputDialog.getText(self, "Add Field", "Enter the name of the new field:")
        if ok and field:
            self.field_list.addItem(field)

    def remove_field(self):
        selected = self.field_list.currentRow()
        if selected >= 0:
            self.field_list.takeItem(selected)

    def save_config(self):
        fields = [self.field_list.item(i).text() for i in range(self.field_list.count())]
        self.config["fields"] = fields
        save_config(self.config)
        self.parent.config = load_config()
        self.parent.load_fields()
        QMessageBox.information(self, "Success", "Configuration saved!")
        self.close()

# Main application window
class StoreApp(QWidget):
    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.initUI()
        self.converter_window = None # Instance okna pro převod měn

    def initUI(self):
        self.setWindowTitle("Trade Management")
        self.layout = QVBoxLayout()
        self.form_layout = QFormLayout()
        self.field_inputs = {}
        self.load_fields()

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(QLabel("Enter Password:"))
        self.layout.addWidget(self.password_input)

        self.save_button = QPushButton("Create Trade")
        self.save_button.clicked.connect(self.save_store)
        self.layout.addWidget(self.save_button)

        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Enter token for decryption")
        self.layout.addWidget(self.token_input)

        self.decrypt_button = QPushButton("Decrypt Trade")
        self.decrypt_button.clicked.connect(self.decrypt_store)
        self.layout.addWidget(self.decrypt_button)

        self.config_button = QPushButton("Set Fields")
        self.config_button.clicked.connect(self.open_config_editor)
        self.layout.addWidget(self.config_button)

        # Přidání tlačítka pro otevření okna převodníku měn
        self.converter_button = QPushButton("Currency Converter")
        self.converter_button.clicked.connect(self.open_currency_converter)
        self.layout.addWidget(self.converter_button)

        self.setLayout(self.layout)

    def load_fields(self):
        for i in reversed(range(self.form_layout.count())):
            self.form_layout.itemAt(i).widget().setParent(None)
        self.field_inputs.clear()
        for field in self.config.get("fields", []):
            field_input = QLineEdit()
            self.field_inputs[field] = field_input
            self.form_layout.addRow(QLabel(field), field_input)
        if not hasattr(self, 'field_container'):
            self.field_container = QWidget()
            self.field_container.setLayout(self.form_layout)
            self.layout.insertWidget(2, self.field_container)

    def open_config_editor(self):
        self.config_editor = ConfigEditor(self)
        self.config_editor.show()

    def open_currency_converter(self):
        if self.converter_window is None:
            self.converter_window = CurrencyConverter(self)
        self.converter_window.show()

    def save_store(self):
        store_data = {field: self.field_inputs[field].text() for field in self.field_inputs}
        password = self.password_input.text()
        token = encrypt_store(store_data, password)
        pyperclip.copy(token)
        self.token_input.clear()
        for field in self.field_inputs.values():
            field.clear()
        QMessageBox.information(self, "Success", "Trade encrypted and token copied to clipboard!")

    def decrypt_store(self):
        try:
            store_data = decrypt_store(self.token_input.text(), self.password_input.text())
            QMessageBox.information(self, "Decrypted", json.dumps(store_data, indent=4))
        except Exception:
            QMessageBox.warning(self, "Error", "Signature is invalid or data is corrupted!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = StoreApp()
    window.show()
    sys.exit(app.exec_())