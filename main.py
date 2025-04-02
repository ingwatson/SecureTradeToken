import sys
import json
import os
import hashlib
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import HMAC, SHA256
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, QPushButton,
                             QVBoxLayout, QFormLayout, QMessageBox, QHBoxLayout, QListWidget, QInputDialog)
import pyperclip  # Для работы с буфером обмена

CONFIG_FILE = "config.json"

# Функция для генерации ключа из пароля
def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

# Функция для загрузки конфигурации
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {"fields": []}

# Функция для сохранения конфигурации
def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

# Функция для шифрования сделки
def encrypt_trade(trade_data: dict, password: str) -> str:
    data_json = json.dumps(trade_data)
    salt = os.urandom(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(data_json.encode(), AES.block_size))

    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(iv + encrypted_data)
    signature = hmac.digest()

    return base64.b64encode(salt + iv + encrypted_data + signature).decode()

# Функция для расшифровки сделки
def decrypt_trade(token: str, password: str) -> dict:
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

# Окно для редактирования полей
class ConfigEditor(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.setWindowTitle("Настройка полей сделки")
        self.layout = QVBoxLayout()
        self.field_list = QListWidget()
        self.config = load_config()

        self.reload_fields()
        self.layout.addWidget(self.field_list)

        self.add_button = QPushButton("Добавить поле")
        self.add_button.clicked.connect(self.add_field)
        self.layout.addWidget(self.add_button)

        self.remove_button = QPushButton("Удалить выбранное поле")
        self.remove_button.clicked.connect(self.remove_field)
        self.layout.addWidget(self.remove_button)

        self.save_button = QPushButton("Сохранить")
        self.save_button.clicked.connect(self.save_config)
        self.layout.addWidget(self.save_button)

        self.setLayout(self.layout)

    def reload_fields(self):
        self.field_list.clear()
        for field in self.config["fields"]:
            self.field_list.addItem(field)

    def add_field(self):
        field, ok = QInputDialog.getText(self, "Добавить поле", "Введите название нового поля:")
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
        self.parent.reload_fields()
        QMessageBox.information(self, "Успех", "Конфигурация сохранена!")
        self.close()

# Основное окно приложения
class TradeApp(QWidget):
    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Управление сделками")
        self.layout = QVBoxLayout()
        self.form_layout = QFormLayout()
        self.field_inputs = {}
        self.reload_fields()

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(QLabel("Введите пароль:"))
        self.layout.addWidget(self.password_input)

        self.save_button = QPushButton("Создать сделку")
        self.save_button.clicked.connect(self.save_trade)
        self.layout.addWidget(self.save_button)

        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Вставьте токен для расшифровки")
        self.layout.addWidget(self.token_input)

        self.decrypt_button = QPushButton("Расшифровать сделку")
        self.decrypt_button.clicked.connect(self.decrypt_trade)
        self.layout.addWidget(self.decrypt_button)

        self.config_button = QPushButton("Настроить поля")
        self.config_button.clicked.connect(self.open_config_editor)
        self.layout.addWidget(self.config_button)

        self.setLayout(self.layout)

    def reload_fields(self):
        for i in reversed(range(self.form_layout.count())):
            self.form_layout.itemAt(i).widget().setParent(None)
        self.field_inputs.clear()
        for field in self.config.get("fields", []):
            input_field = QLineEdit()
            self.field_inputs[field] = input_field
            self.form_layout.addRow(QLabel(field), input_field)
        if not hasattr(self, 'fields_container'):
            self.fields_container = QWidget()
            self.fields_container.setLayout(self.form_layout)
            self.layout.insertWidget(2, self.fields_container)

    def open_config_editor(self):
        self.config_editor = ConfigEditor(self)
        self.config_editor.show()

    def save_trade(self):
        trade_data = {field: self.field_inputs[field].text() for field in self.field_inputs}
        password = self.password_input.text()
        token = encrypt_trade(trade_data, password)
        pyperclip.copy(token)
        self.token_input.clear()
        for field in self.field_inputs.values():
            field.clear()
        QMessageBox.information(self, "Успех", "Сделка зашифрована и токен скопирован в буфер обмена!")

    def decrypt_trade(self):
        try:
            trade_data = decrypt_trade(self.token_input.text(), self.password_input.text())
            QMessageBox.information(self, "Расшифровано", json.dumps(trade_data, indent=4))
        except Exception:
            QMessageBox.warning(self, "Ошибка", "Подпись неверна или данные повреждены!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TradeApp()
    window.show()
    sys.exit(app.exec_())
