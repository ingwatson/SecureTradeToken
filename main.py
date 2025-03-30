import sys
import json
import os
import hashlib
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import HMAC, SHA256
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QFormLayout, QMessageBox
import pyperclip  # Для работы с буфером обмена

# Функция для генерации ключа из пароля с использованием PBKDF2
def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

# Функция для шифрования сделки
def encrypt_trade(trade_data: dict, password: str) -> str:
    data_json = json.dumps(trade_data)  # Преобразуем данные в JSON-строку
    salt = os.urandom(16)  # Генерируем случайную соль (для ключа)
    key = derive_key(password, salt)  # Генерируем ключ из пароля
    cipher = AES.new(key, AES.MODE_CBC)  # Создаём AES-шифратор в режиме CBC
    iv = cipher.iv  # Получаем случайный вектор инициализации
    encrypted_data = cipher.encrypt(pad(data_json.encode(), AES.block_size))  # Шифруем и падируем данные

    # Генерируем HMAC (контрольную подпись, чтобы проверить целостность данных)
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(iv + encrypted_data)  # Подписываем IV + зашифрованные данные
    signature = hmac.digest()  # Получаем HMAC-подпись

    # Кодируем все части в Base64 (salt + IV + зашифрованные данные + подпись)
    return base64.b64encode(salt + iv + encrypted_data + signature).decode()

# Функция для расшифровки сделки
def decrypt_trade(token: str, password: str) -> dict:
    raw_data = base64.b64decode(token)  # Декодируем Base64-строку
    salt = raw_data[:16]  # Извлекаем соль
    iv = raw_data[16:32]  # Извлекаем IV (16 байт)
    encrypted_data = raw_data[32:-32]  # Извлекаем зашифрованные данные (до HMAC)
    signature = raw_data[-32:]  # Извлекаем HMAC-подпись

    key = derive_key(password, salt)  # Генерируем ключ из пароля и соли

    # Проверяем HMAC-подпись
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(iv + encrypted_data)
    try:
        hmac.verify(signature)  # Если подпись неверна, выбросится исключение
    except ValueError:
        return None

    # Расшифровываем данные
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)  # Дешифруем и удаляем паддинг
    return json.loads(decrypted_data.decode())  # Возвращаем JSON-объект

class TradeEncryptionApp(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Шифрование Сделок')
        self.setGeometry(100, 100, 600, 400)

        self.init_ui()

    def init_ui(self):
        # Создаём виджеты
        self.id_input = QLineEdit(self)
        self.type_input = QLineEdit(self)
        self.item_input = QLineEdit(self)
        self.price_input = QLineEdit(self)
        self.date_input = QLineEdit(self)
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)

        # Для расшифровки
        self.token_input = QLineEdit(self)
        self.token_input.setPlaceholderText("Вставьте токен для расшифровки")

        # Кнопки
        self.encrypt_button = QPushButton('Шифровать сделку', self)
        self.encrypt_button.clicked.connect(self.encrypt_trade)

        self.decrypt_button = QPushButton('Расшифровать токен', self)
        self.decrypt_button.clicked.connect(self.decrypt_trade)

        # Размещение элементов на экране
        form_layout = QFormLayout()
        form_layout.addRow('ID сделки:', self.id_input)
        form_layout.addRow('Тип сделки:', self.type_input)
        form_layout.addRow('Предмет сделки:', self.item_input)
        form_layout.addRow('Цена сделки:', self.price_input)
        form_layout.addRow('Дата сделки:', self.date_input)
        form_layout.addRow('Пароль:', self.password_input)
        form_layout.addRow('Токен для расшифровки:', self.token_input)

        button_layout = QVBoxLayout()
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)

        layout = QVBoxLayout()
        layout.addLayout(form_layout)
        layout.addLayout(button_layout)
        self.setLayout(layout)

    def clear_inputs(self):
        # Очищаем все поля ввода
        self.id_input.clear()
        self.type_input.clear()
        self.item_input.clear()
        self.price_input.clear()
        self.date_input.clear()
        self.password_input.clear()
        self.token_input.clear()

    def encrypt_trade(self):
        try:
            # Проверка правильности ввода
            if not self.id_input.text() or not self.type_input.text() or not self.item_input.text() or not self.price_input.text() or not self.date_input.text() or not self.password_input.text():
                self.show_error('Ошибка', 'Пожалуйста, заполните все поля!')
                return

            trade = {
                "id": int(self.id_input.text()),
                "type": self.type_input.text(),
                "item": self.item_input.text(),
                "price": float(self.price_input.text()),
                "date": self.date_input.text()
            }
            password = self.password_input.text()
            token = encrypt_trade(trade, password)
            pyperclip.copy(token)  # Копируем токен в буфер обмена
            self.clear_inputs()  # Очищаем поля ввода после шифрования
            self.show_info('Успех', 'Сделка успешно зашифрована! Токен скопирован в буфер обмена.')

        except ValueError:
            self.show_error('Ошибка', 'Пожалуйста, заполните все поля корректно.')

    def decrypt_trade(self):
        try:
            token = self.token_input.text().strip()  # Получаем токен из поля
            if not token:
                self.show_error('Ошибка', 'Пожалуйста, вставьте токен для расшифровки.')
                return

            password = self.password_input.text()
            restored_trade = decrypt_trade(token, password)
            if restored_trade:
                self.show_info('Успех', f'Сделка успешно расшифрована! Данные: {json.dumps(restored_trade, indent=4)}')
                self.clear_inputs()  # Очищаем поля после расшифровки
            else:
                self.show_error('Ошибка', 'Подпись HMAC неверна или данные повреждены.')
        except ValueError:
            self.show_error('Ошибка', 'Пожалуйста, введите корректный токен.')

    def show_error(self, title, message):
        QMessageBox.critical(self, title, message)

    def show_info(self, title, message):
        QMessageBox.information(self, title, message)

def main():
    app = QApplication(sys.argv)
    window = TradeEncryptionApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()