import sys
import json
import os
import hashlib
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import HMAC, SHA256
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, QPushButton,
                             QVBoxLayout, QFormLayout, QMessageBox, QHBoxLayout)
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
    return {"fields": ["ID", "Type", "Created by:", "Customer name:", "Customer ID-number:", "Date", "Price", "Notes:"]}

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

# Основной GUI-класс
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

        # Генерация полей из конфигурации
        for field in self.config["fields"]:
            input_field = QLineEdit()
            self.field_inputs[field] = input_field
            self.form_layout.addRow(QLabel(field), input_field)

        self.layout.addLayout(self.form_layout)

        # Поле для ввода пароля
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(QLabel("Введите пароль:"))
        self.layout.addWidget(self.password_input)

        # Кнопка сохранения
        self.save_button = QPushButton("Создать сделку")
        self.save_button.clicked.connect(self.save_trade)
        self.layout.addWidget(self.save_button)

        # Поле для вставки токена
        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Вставьте токен для расшифровки")
        self.layout.addWidget(self.token_input)

        # Кнопка расшифровки
        self.decrypt_button = QPushButton("Расшифровать сделку")
        self.decrypt_button.clicked.connect(self.decrypt_trade)
        self.layout.addWidget(self.decrypt_button)

        self.setLayout(self.layout)

    def save_trade(self):
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Ошибка", "Введите пароль для шифрования!")
            return

        trade_data = {field: self.field_inputs[field].text() for field in self.field_inputs}
        token = encrypt_trade(trade_data, password)
        pyperclip.copy(token)
        QMessageBox.information(self, "Успех", "Сделка зашифрована и токен скопирован в буфер обмена!")

    def decrypt_trade(self):
        password = self.password_input.text()
        token = self.token_input.text()
        if not token:
            QMessageBox.warning(self, "Ошибка", "Введите токен для расшифровки!")
            return
        if not password:
            QMessageBox.warning(self, "Ошибка", "Введите пароль для расшифровки!")
            return
        try:
            trade_data = decrypt_trade(token, password)
            QMessageBox.information(self, "Расшифрованные данные", json.dumps(trade_data, indent=4, ensure_ascii=False))
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось расшифровать сделку: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TradeApp()
    window.show()
    sys.exit(app.exec_())
