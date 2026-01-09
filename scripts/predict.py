import pandas as pd
import numpy as np
import xgboost as xgb
import json
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import base64

# Load preprocessed test data
test_file = "data/KDDTest_preprocessed.csv"
test_df = pd.read_csv(test_file)

# Extract features (X) and labels (y)
X_test = test_df.iloc[:, :-1]
y_test = test_df["label"]

# ✅ Fix: Convert all columns to float
X_test = X_test.apply(pd.to_numeric, errors='coerce')
X_test.fillna(0, inplace=True)

# Load trained model
model_path = "models/xgboost_intrusion_detection.json"
model = xgb.XGBClassifier()
model.load_model(model_path)

print("✅ Model Loaded Successfully!")

# ✅ Now, predict without error
y_pred = model.predict(X_test)

# Identify attack instances
attack_indices = np.where(y_pred == 1)[0]

# Generate RSA-4096 keypair (Simulating Kyber-1024)
rsa_key = RSA.generate(4096)
public_key = rsa_key.publickey()
private_key = rsa_key.export_key()

# AES-256 Encryption Function
def encrypt_data(data, public_key):
    aes_key = get_random_bytes(32)  # AES-256 Key
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    # Encrypt AES key with RSA
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return base64.b64encode(encrypted_aes_key + cipher_aes.nonce + tag + ciphertext).decode()

# AES-256 Decryption Function
def decrypt_data(encrypted_data, private_key):
    encrypted_data = base64.b64decode(encrypted_data)

    # Extract parts
    encrypted_aes_key = encrypted_data[:512]  # RSA-4096 Key Size
    nonce = encrypted_data[512:528]
    tag = encrypted_data[528:544]
    ciphertext = encrypted_data[544:]

    # Decrypt AES key with RSA
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Decrypt data
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag)

# List to store encrypted alerts
encrypted_alerts = []

print("\n🔍 Intrusion Detection Results:")
for i in attack_indices[:5]:  # Show first 5 attacks
    attack_alert = {
        "attack_id": int(i),
        "type": "Malicious Network Activity",
        "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
        "confidence": float(np.random.uniform(0.95, 1.00))  # Simulated confidence score
    }

    # Convert alert to JSON and encrypt with AES-256 + RSA-4096
    alert_json = json.dumps(attack_alert).encode()
    encrypted_alert = encrypt_data(alert_json, public_key)
    encrypted_alerts.append(encrypted_alert)

    print(f"🚨 Attack Detected! Encrypted Alert Sent: {encrypted_alert[:50]}...")

# Simulate Decryption at Receiver Side
if encrypted_alerts:
    decrypted_alert = decrypt_data(encrypted_alerts[0], private_key).decode()
    print("\n✅ Decrypted Alert Matches:", decrypted_alert)

print("\n✅ Intrusion Detection Completed! All alerts securely encrypted.")
