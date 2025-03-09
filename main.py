import base64
import hashlib
import os
import time
import keyboard
import brotli
import psutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key


# Функция для добавления padding'а
def pad(data, block_size=16):
    missing_padding = block_size - len(data) % block_size
    padding_char = bytes([missing_padding])  # Добавляется символ, соответствующий количеству недостающих байтов
    return data + padding_char * missing_padding


# Функция для удаления padding'а
def unpad(s):
    last_byte = s[-1]
    if isinstance(last_byte, int):
        last_byte = bytes([last_byte])
    return s[:-int.from_bytes(last_byte, byteorder='big')]  # Конвертируем байт в целое число


# Генерация ключей
def generate_aes_key():
    return os.urandom(32)


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def generate_one_time_pad(key_length):
    return os.urandom(key_length)


# Шифрование AES
def aes_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad(data)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext


def aes_decrypt(ciphertext_with_iv, key):
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpad(padded_plaintext)
    return plaintext


# Шифрование RSA
def rsa_encrypt(data, public_key):
    cipher = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher


def rsa_decrypt(encrypted_data, private_key):
    plain_text = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain_text


# Шифр Вернама
def vernam_encrypt(data, one_time_pad):
    if len(one_time_pad) != len(data):
        raise ValueError(f"Длина ключа ({len(one_time_pad)}) не совпадает с длиной данных ({len(data)}).")
    ciphertext = bytes([a ^ b for a, b in zip(data, one_time_pad)])
    return ciphertext


def vernam_decrypt(ciphertext, one_time_pad):
    if len(one_time_pad) != len(ciphertext):
        raise ValueError(
            f"Длина ключа ({len(one_time_pad)}) не совпадает с длиной зашифрованных данных ({len(ciphertext)}).")
    plaintext = bytes([a ^ b for a, b in zip(ciphertext, one_time_pad)])
    return plaintext


# HMAC для аутентификации
def hmac_sign(message, key):
    h = hashlib.sha256(key)
    h.update(message)
    return h.digest()


# Безопасное сравнение строк (замена compare_digest)
def safe_compare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def hmac_verify(received_message, received_hmac, key):
    expected_hmac = hmac_sign(received_message, key)
    return safe_compare(expected_hmac, received_hmac)


# Полная схема шифрования
def encrypt_message(message, rsa_public_key):
    compressed_message = brotli.compress(message.encode())  # Сжимаем сообщение перед шифрованием

    # Шаг 1: Шифруем сообщение с помощью AES
    aes_key = generate_aes_key()
    ciphertext_aes = aes_encrypt(compressed_message, aes_key)

    # Шаг 2: Шифруем ключ AES с помощью RSA
    encrypted_aes_key = rsa_encrypt(aes_key, rsa_public_key)

    # Шаг 3: Применяем шифр Вернама к зашифрованному сообщению
    one_time_pad_key_for_vernam = generate_one_time_pad(len(ciphertext_aes))
    ciphertext_vernam = vernam_encrypt(ciphertext_aes, one_time_pad_key_for_vernam)

    # Шаг 4: Подписываем сообщение с помощью HMAC
    hmac_key = os.urandom(32)
    message_hmac = hmac_sign(ciphertext_vernam, hmac_key)

    # Собираем все части вместе
    encrypted_parts = {
        'aes_key': base64.b64encode(encrypted_aes_key).decode(),
        'ciphertext': base64.b64encode(ciphertext_vernam).decode(),
        'hmac': base64.b64encode(message_hmac).decode(),
        'hmac_key': base64.b64encode(hmac_key).decode(),
        'one_time_key': base64.b64encode(one_time_pad_key_for_vernam).decode()
    }

    return encrypted_parts


def decrypt_message(encrypted_parts, rsa_private_key):
    # Декодируем все части
    encrypted_aes_key = base64.b64decode(encrypted_parts['aes_key'].encode())
    ciphertext_vernam = base64.b64decode(encrypted_parts['ciphertext'].encode())
    message_hmac = base64.b64decode(encrypted_parts['hmac'].encode())
    hmac_key = base64.b64decode(encrypted_parts['hmac_key'].encode())
    one_time_pad_key_for_vernam = base64.b64decode(encrypted_parts['one_time_key'].encode())

    # Проверка целостности сообщения
    if not hmac_verify(ciphertext_vernam, message_hmac, hmac_key):
        raise Exception("Сообщение было изменено!")

    # Шаг 1: Расшифровка ключа AES с помощью RSA
    aes_key = rsa_decrypt(encrypted_aes_key, rsa_private_key)

    # Шаг 2: Расшифровка сообщения с помощью шифра Вернама
    ciphertext_aes = vernam_decrypt(ciphertext_vernam, one_time_pad_key_for_vernam)

    # Шаг 3: Расшифровка AES
    compressed_message = aes_decrypt(ciphertext_aes, aes_key)

    # Шаг 4: Распаковка сжатого сообщения
    message = brotli.decompress(compressed_message).decode()

    return message


if __name__ == "__main__":
    encdec = int(input('зашифровать - 1, рашсшифровать = 2' + '\n'))
    if encdec == 1:
        file_text = input('путь к файлу с текстом: ')
        file_res = input('путь к файлу для записи зашифроваанного сообщения: ')
        # Генерация ключей
        rsa_private_key, rsa_public_key = generate_rsa_keys()

        with open(file_text, 'r', encoding='utf-8') as file:
            message = file.read()

        # Шифрование сообщения
        start_time = time.time()
        encrypted_message = encrypt_message(message, rsa_public_key)
        end_time = time.time()

        rsa_private_key_str = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        # запись зашифрованного сообщения в файл
        with open(file_res, 'w', encoding='utf-8') as file:
            file.write('private_key: ' + '\n' + rsa_private_key_str + '\n' +
                       'aes_key: ' + '\n' + encrypted_message['aes_key'] + '\n' +
                       'ciphertext: ' + '\n' + encrypted_message['ciphertext'] + '\n' +
                       'hmac: ' + '\n' + encrypted_message['hmac'] + '\n' +
                       'hmac_key: ' + '\n' + encrypted_message['hmac_key'] + '\n' +
                       'one_time_key' + '\n' + encrypted_message['one_time_key'])

    else:
        file_cipher = input('путь к файлу с шифром: ')
        file_res = input('путь к файлу для записи расшифрованного сообщения: ')
        with open(file_cipher, 'r', encoding='utf-8') as file:
            dectext = file.readlines()

        rsa_private_key_str = ''
        for i in range(1, 28):
            rsa_private_key_str += dectext[i]

        encrypted_message = {
            'aes_key': dectext[30][:-1],
            'ciphertext': dectext[32][:-1],
            'hmac': dectext[34][:-1],
            'hmac_key': dectext[36][:-1],
            'one_time_key': dectext[38]
        }

        rsa_private_key = load_pem_private_key(rsa_private_key_str.encode(), password=None,
                                                        backend=default_backend())
        # Расшифровка сообщения
        start_time = time.time()
        decrypted_message = decrypt_message(encrypted_message, rsa_private_key)
        end_time = time.time()

        with open(file_res, 'w', encoding='utf-8') as file:
            file.write(decrypted_message)

    print('successful')
    print(f"Время выполнения: {end_time - start_time} секунд")
    process = psutil.Process()
    print(f"Используемая память: {process.memory_info().rss / 2**20} Мбайт")
    print('Для завершения нажмите любую клавишу...')
    keyboard.read_key()
