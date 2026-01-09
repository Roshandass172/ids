from cryptography.fernet import Fernet

# Generate a secret key (Only run this once, save the key)
# key = Fernet.generate_key()
# with open("security/secret.key", "wb") as key_file:
#     key_file.write(key)

# Load the secret key AES128
with open("security/secret.key", "rb") as key_file:
    secret_key = key_file.read()

cipher = Fernet(secret_key)

def encrypt_alert(alert_message):
    """Encrypts security alerts using Fernet encryption."""
    return cipher.encrypt(alert_message.encode()).decode()

def decrypt_alert(encrypted_message):
    """Decrypts encrypted security alerts."""
    return cipher.decrypt(encrypted_message.encode()).decode()
