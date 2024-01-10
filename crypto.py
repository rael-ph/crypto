from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

def read_adm_password():
    try:
        with open("adm_password.txt", "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        return "back-up_password"

def check_adm_password(input_password):
    stored_password = read_adm_password()
    return stored_password == input_password

def generate_key(password):
    password = password.encode()
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=1000000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_text(text, key):
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(text.encode())
    return encrypted_text

def decrypt_text(encrypted_text, key):
    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(encrypted_text)
    return decrypted_text.decode()

def compact_text(text):
    return text.replace('\n', '<newline>').replace('\r', '<return>')

def decompress_text(compacted_text):
    return compacted_text.replace('<newline>', '\n').replace('<return>', '\r')

def compact_and_encrypt():
    text = input("Digite o texto completo com quebras de linha (digite 'fim' para finalizar):\n")
    lines = []
    while True:
        line = input()
        if line.lower() == 'fim':
            break
        lines.append(line)

    text = '\n'.join(lines)
    compacted_text = compact_text(text)

    password = input("Digite a chave para criptografar: ")
    key = generate_key(password)
    encrypted_text = encrypt_text(compacted_text, key)

    print(f"Texto Compactado e Criptografado: {encrypted_text}")

def decrypt_and_decompress():
    encrypted_text = input("Digite o texto criptografado: ")
    password = input("Digite a chave para descriptografar: ")

    key = generate_key(password)
    decrypted_text = decrypt_text(encrypted_text, key)
    decompressed_text = decompress_text(decrypted_text)

    print(f"Texto Descriptografado e Descompactado:\n{decompressed_text}")

# Execução principal do programa
if __name__ == "__main__":
    attempts_left = 3

    while attempts_left > 0:
        user_password = input("Digite a senha: ")

        if check_adm_password(user_password):
            print("Senha correta. Acesso concedido.")
            break
        else:
            attempts_left -= 1
            if attempts_left > 0:
                print(f"Senha incorreta. Tentativas restantes: {attempts_left}")
            else:
                print("Número de tentativas excedido. O programa será encerrado.")
                break

    if attempts_left > 0:
        while True:
            choice = input("C - compactar e criptografar\nD - descriptografar e descompactar\nENTER - encerrar\ninput: ").upper()

            if choice == "C":
                compact_and_encrypt()
            elif choice == "D":
                decrypt_and_decompress()
            else:
                print("----------")
                break
