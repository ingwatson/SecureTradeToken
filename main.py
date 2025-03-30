from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import HMAC, SHA256
import base64
import json
import os
import hashlib

# Функция для генерации ключа из пароля с использованием PBKDF2
# Это делает ключ более безопасным, так как хэширует пароль
def derive_key(password: str, salt: bytes) -> bytes:
    """Генерирует 32-байтовый AES-ключ из пароля."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

# Функция для шифрования сделки
def encrypt_trade(trade_data: dict, password: str) -> str:
    """Шифрует данные сделки, создаёт HMAC и возвращает токен."""
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
    """Расшифровывает токен, проверяет подпись HMAC и возвращает данные сделки."""
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
        hmac.verify(signature)  # Если подпись неверная, выбросится исключение
    except ValueError:
        print("Подпись HMAC неверна. Данные были повреждены.")
        return {}

    # Расшифровываем данные
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)  # Дешифруем и удаляем паддинг
    return json.loads(decrypted_data.decode())  # Возвращаем JSON-объект

def create_trade():
    """Создаёт новую сделку."""
    trade = {
        "id": int(input("Введите ID сделки: ")),
        "type": input("Введите тип сделки: "),
        "item": input("Введите предмет сделки: "),
        "price": float(input("Введите цену сделки: ")),
        "date": input("Введите дату сделки (гггг-мм-дд): ")
    }
    return trade

def main():
    print("Добро пожаловать в систему шифрования сделок!")

    while True:
        choice = input("Выберите действие (1 - создать новую сделку, 2 - расшифровать существующую, 3 - выйти): ")

        if choice == '1':
            password = input("Введите пароль для шифрования: ")  # Пароль для шифрования
            trade = create_trade()  # Создаём новую сделку
            # Шифруем сделку и получаем токен
            token = encrypt_trade(trade, password)
            print(f"Сгенерированный токен: {token}")

        elif choice == '2':
            token = input("Введите токен для расшифровки: ")
            password = input("Введите пароль для расшифровки: ")
            # Расшифровываем сделку из токена
            restored_trade = decrypt_trade(token, password)
            if restored_trade:
                print(f"Восстановленные данные: {restored_trade}")
            else:
                print("Не удалось расшифровать токен.")

        elif choice == '3':
            print("Выход из программы.")
            break

        else:
            print("Неверный выбор. Пожалуйста, выберите 1, 2 или 3.")

if __name__ == "__main__":
    main()