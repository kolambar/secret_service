import hashlib
from typing import Tuple

from Crypto.Cipher import AES


def hash_it(user_key: str) -> str:
    """
    Функция кэширует ключ, чтобы поместить кэш в бд и чтобы кэшировать ключ и найти по кэшу в бд секрет
    :param user_key:
    :return hash_key:
    """
    return hashlib.sha256(user_key.encode()).hexdigest()


def pad_data(data: bytes, block_size: int = 16) -> bytes:
    """
    Функция преобразует строку в нужный размер для последующей кодировки.
    :param data:
    :param block_size:
    :return padded_data:
    """
    padding = block_size - len(data) % block_size
    padded_data = data + bytes([padding] * padding)
    return padded_data


def code_it(user_key: str, secret: str) -> bytes:
    """
    Функция для кодировки тайны
    :param user_key:
    :param secret:
    :return ciphertext + tag + nonce:
    """
    # Подготавливаем ключ
    padded_key = pad_data(user_key.encode('utf-8'), 16)

    # Подготавливаем данные для шифрования
    padded_plaintext = pad_data(secret.encode('utf-8'), 16)

    # Создает новый объект шифра AES
    cipher = AES.new(padded_key, AES.MODE_EAX)

    # Получаем nonce нужен для обеспечения безопасности аутентификации данных
    nonce = cipher.nonce

    # Шифруем данные и получаем зашифрованный текст и тэг для проверки
    ciphertext, tag = cipher.encrypt_and_digest(padded_plaintext)

    return ciphertext + tag + nonce


def extract_encrypted_parts(encrypted_data: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Извлекает зашифрованные части из байтов.
    :param encrypted_data: Байты, содержащие зашифрованные данные (ciphertext, tag, nonce).
    :return: Кортеж, содержащий зашифрованный текст (ciphertext), тег (tag) и nonce.
    """
    # Размер блока равен 16 байтам
    block_size = 16

    # Извлекаем размеры данных
    ciphertext_size = len(encrypted_data) - 2 * block_size
    tag_size = block_size

    # Извлекаем значения из строки encrypted_data
    ciphertext = encrypted_data[:ciphertext_size]  # Длина зашифрованного текста (block size)
    tag = encrypted_data[ciphertext_size:ciphertext_size + tag_size]  # Длина тега
    nonce = encrypted_data[ciphertext_size + tag_size:]  # Остаток - длина nonce

    return ciphertext, tag, nonce


def decode_it(user_key: str, encrypted_data: bytes) -> str:
    """
    Функция для декодировки тайны
    :param user_key:
    :param encrypted_data:
    :return decrypted_text:
    """
    # Извлекает зашифрованные части из байтов
    ciphertext, tag, nonce = extract_encrypted_parts(encrypted_data)
    # Преобразует строку в нужный размер для последующей кодировки.
    padded_key = pad_data(user_key.encode('utf-8'), 16)

    # Создает decipher для расшифровки
    decipher = AES.new(padded_key, AES.MODE_EAX, nonce=nonce)  # передает ему тот же nonce, что создался при кодировке

    # Расшифровывает текст
    decrypted_text = decipher.decrypt_and_verify(ciphertext, tag).decode().rstrip('\n\u0010\b\u0007\x05')  # отрезает лишние символы

    return decrypted_text
