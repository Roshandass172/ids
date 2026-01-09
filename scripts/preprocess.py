import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

# Define column names for NSL-KDD dataset
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label"
]

# Load datasets
train_file = "data/KDDTrain+.txt"
test_file = "data/KDDTest+.txt"

train_df = pd.read_csv(train_file, names=columns, header=None)
test_df = pd.read_csv(test_file, names=columns, header=None)

# Drop duplicate rows (if any)
train_df.drop_duplicates(inplace=True)
test_df.drop_duplicates(inplace=True)

### **1️⃣ Convert attack labels to binary classification (normal = 0, attack = 1)**
def convert_label(value):
    """Ensures labels are only 0 (normal) or 1 (attack)."""
    return 0 if int(value) == 0 else 1  # Convert all non-zero labels to 1

train_df["label"] = train_df["label"].apply(convert_label)
test_df["label"] = test_df["label"].apply(convert_label)

# Print label distribution before balancing
print("✅ Training Labels Before Balancing:\n", train_df["label"].value_counts())
print("✅ Testing Labels Before Balancing:\n", test_df["label"].value_counts())

### **2️⃣ Handle Imbalanced Data by Oversampling Normal Traffic**
normal_samples = train_df[train_df["label"] == 0]
attack_samples = train_df[train_df["label"] == 1]

# Oversample normal traffic to match attack samples
if len(normal_samples) < len(attack_samples):
    normal_oversampled = normal_samples.sample(n=len(attack_samples), replace=True, random_state=42)
    train_df = pd.concat([normal_oversampled, attack_samples]).sample(frac=1, random_state=42)

# Print label distribution after balancing
print("✅ Balanced Training Labels:\n", train_df["label"].value_counts())

### **3️⃣ Encode Categorical Features (protocol_type, service, flag)**
categorical_columns = ["protocol_type", "service", "flag"]
encoders = {}

for col in categorical_columns:
    encoders[col] = LabelEncoder()
    train_df[col] = encoders[col].fit_transform(train_df[col])
    # Handle unseen categories in test data
    test_df[col] = test_df[col].apply(lambda x: x if x in encoders[col].classes_ else "Unknown")
    encoders[col].classes_ = np.append(encoders[col].classes_, "Unknown")
    test_df[col] = encoders[col].transform(test_df[col])

### **4️⃣ Normalize Numerical Features Using MinMaxScaler**
numeric_features = train_df.select_dtypes(include=[np.number]).columns.tolist()
numeric_features.remove("label")  # Exclude target column

scaler = MinMaxScaler()
train_df[numeric_features] = scaler.fit_transform(train_df[numeric_features])
test_df[numeric_features] = scaler.transform(test_df[numeric_features])

# Split dataset into features (X) and labels (y)
X_train, y_train = train_df[numeric_features], train_df["label"]
X_test, y_test = test_df[numeric_features], test_df["label"]

# Ensure labels are strictly 0 or 1
train_df["label"] = train_df["label"].apply(lambda x: 1 if x > 0.5 else 0).astype(int)
test_df["label"] = test_df["label"].apply(lambda x: 1 if x > 0.5 else 0).astype(int)

# Verify final label values
print("✅ Final Training Labels Unique Values:", train_df["label"].unique())
print("✅ Final Testing Labels Unique Values:", test_df["label"].unique())

# Save preprocessed datasets
train_df.to_csv("data/KDDTrain_preprocessed.csv", index=False)
test_df.to_csv("data/KDDTest_preprocessed.csv", index=False)
print("✅ Preprocessed data saved in 'data/' folder.")
