import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

# Paths for data
train_file = "data/KDDTrain_preprocessed.csv"
test_file = "data/KDDTest_preprocessed.csv"

# Define column names
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

# Load datasets with proper data types
train_df = pd.read_csv(train_file, names=columns, header=0, low_memory=False)
test_df = pd.read_csv(test_file, names=columns, header=0, low_memory=False)

# Convert all numeric columns to float
numeric_features = train_df.columns[:-1]  # Exclude the label column
train_df[numeric_features] = train_df[numeric_features].apply(pd.to_numeric, errors='coerce')
test_df[numeric_features] = test_df[numeric_features].apply(pd.to_numeric, errors='coerce')

# Fill NaN values with 0
train_df.fillna(0, inplace=True)
test_df.fillna(0, inplace=True)

print("✅ Data successfully loaded with correct types!")

# Drop duplicate rows
train_df.drop_duplicates(inplace=True)
test_df.drop_duplicates(inplace=True)

# Convert labels to strictly 0 or 1
train_df["label"] = train_df["label"].apply(lambda x: 1 if float(x) > 0 else 0).astype(int)
test_df["label"] = test_df["label"].apply(lambda x: 1 if float(x) > 0 else 0).astype(int)

# Print unique labels before training
print("✅ Unique labels in training data:", train_df["label"].unique())
print("✅ Unique labels in testing data:", test_df["label"].unique())

# Encode categorical features
categorical_columns = ["protocol_type", "service", "flag"]
encoders = {}

for col in categorical_columns:
    encoders[col] = LabelEncoder()
    train_df[col] = encoders[col].fit_transform(train_df[col].astype(str))

    # Handle unseen categories in test data
    test_df[col] = test_df[col].astype(str).map(lambda x: x if x in encoders[col].classes_ else "Unknown")
    encoders[col].classes_ = np.append(encoders[col].classes_, "Unknown")
    test_df[col] = encoders[col].transform(test_df[col])

# Normalize numerical features
scaler = MinMaxScaler()
train_df[numeric_features] = scaler.fit_transform(train_df[numeric_features])
test_df[numeric_features] = scaler.transform(test_df[numeric_features])

# Split features (X) and labels (y)
X_train, y_train = train_df.iloc[:, :-1], train_df["label"]
X_test, y_test = test_df.iloc[:, :-1], test_df["label"]

# Train XGBoost model
model = xgb.XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=6,
    use_label_encoder=False,
    eval_metric='logloss'
)
model.fit(X_train, y_train)

# Predictions
y_pred = model.predict(X_test)

# Evaluation metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print(f"🔹 Accuracy: {accuracy:.4f}")
print(f"🔹 Precision: {precision:.4f}")
print(f"🔹 Recall: {recall:.4f}")
print(f"🔹 F1-Score: {f1:.4f}")

# Save trained model
model.save_model("models/xgboost_intrusion_detection.json")
print("✅ Model saved in models/xgboost_intrusion_detection.json")
