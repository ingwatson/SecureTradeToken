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
import pyperclip  # Pro práci se schránkou

CONFIG_FILE = "config.json"

# Funkce pro generování klíče z hesla
def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

# Funkce pro načtení konfigurace
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {"fields": []}

# Funkce pro uložení konfigurace
def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

# Funkce pro šifrování obchodu
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

# Funkce pro dešifrování obchodu
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

# Okno pro úpravu polí
class ConfigEditor(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.setWindowTitle("Nastavení polí obchodu")
        self.layout = QVBoxLayout()
        self.field_list = QListWidget()
        self.config = load_config()

        self.load_fields()
        self.layout.addWidget(self.field_list)

        self.add_button = QPushButton("Přidat pole")
        self.add_button.clicked.connect(self.add_field)
        self.layout.addWidget(self.add_button)

        self.remove_button = QPushButton("Odstranit vybrané pole")
        self.remove_button.clicked.connect(self.remove_field)
        self.layout.addWidget(self.remove_button)

        self.save_button = QPushButton("Uložit")
        self.save_button.clicked.connect(self.save_config)
        self.layout.addWidget(self.save_button)

        self.setLayout(self.layout)

    def load_fields(self):
        self.field_list.clear()
        for field in self.config["fields"]:
            self.field_list.addItem(field)

    def add_field(self):
        field, ok = QInputDialog.getText(self, "Přidat pole", "Zadejte název nového pole:")
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
        QMessageBox.information(self, "Úspěch", "Konfigurace uložena!")
        self.close()

# Hlavní okno aplikace
class StoreApp(QWidget):
    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Správa obchodů")
        self.layout = QVBoxLayout()
        self.form_layout = QFormLayout()
        self.field_inputs = {}
        self.load_fields()

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(QLabel("Zadejte heslo:"))
        self.layout.addWidget(self.password_input)

        self.save_button = QPushButton("Vytvořit obchod")
        self.save_button.clicked.connect(self.save_store)
        self.layout.addWidget(self.save_button)

        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Vložte token pro dešifrování")
        self.layout.addWidget(self.token_input)

        self.decrypt_button = QPushButton("Dešifrovat obchod")
        self.decrypt_button.clicked.connect(self.decrypt_store)
        self.layout.addWidget(self.decrypt_button)

        self.config_button = QPushButton("Nastavit pole")
        self.config_button.clicked.connect(self.open_config_editor)
        self.layout.addWidget(self.config_button)

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

    def save_store(self):
        store_data = {field: self.field_inputs[field].text() for field in self.field_inputs}
        password = self.password_input.text()
        token = encrypt_store(store_data, password)
        pyperclip.copy(token)
        self.token_input.clear()
        for field in self.field_inputs.values():
            field.clear()
        QMessageBox.information(self, "Úspěch", "Obchod zašifrován a token zkopírován do schránky!")

    def decrypt_store(self):
        try:
            store_data = decrypt_store(self.token_input.text(), self.password_input.text())
            QMessageBox.information(self, "Dešifrováno", json.dumps(store_data, indent=4))
        except Exception:
            QMessageBox.warning(self, "Chyba", "Podpis je neplatný nebo data jsou poškozena!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = StoreApp()
    window.show()
    sys.exit(app.exec_())