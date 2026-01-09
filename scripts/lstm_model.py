import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, BatchNormalization
import numpy as np
import pandas as pd
import os

# ✅ File Paths
train_file = "/mnt/c/Users/S Jananii/OneDrive/Desktop/bits/data/KDDTrain_preprocessed.csv"
test_file = "/mnt/c/Users/S Jananii/OneDrive/Desktop/bits/data/KDDTest_preprocessed.csv"

# ✅ Check if files exist
if not os.path.exists(train_file) or not os.path.exists(test_file):
    raise FileNotFoundError("❌ Training or Testing dataset not found!")

# ✅ Define column names (Same as XGBoost)
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

# ✅ Load datasets
train_df = pd.read_csv(train_file, names=columns, header=0, low_memory=False)
test_df = pd.read_csv(test_file, names=columns, header=0, low_memory=False)

# ✅ Check if "label" column exists
if "label" not in train_df.columns:
    raise KeyError("❌ Column 'label' missing in training data!")

# ✅ Convert numeric features
numeric_features = train_df.columns[:-1]
train_df[numeric_features] = train_df[numeric_features].apply(pd.to_numeric, errors="coerce")
test_df[numeric_features] = test_df[numeric_features].apply(pd.to_numeric, errors="coerce")

# ✅ Fill NaN values with 0
train_df.fillna(0, inplace=True)
test_df.fillna(0, inplace=True)

# ✅ Convert labels to 0 or 1
train_df["label"] = train_df["label"].apply(lambda x: 1 if float(x) > 0 else 0).astype(int)
test_df["label"] = test_df["label"].apply(lambda x: 1 if float(x) > 0 else 0).astype(int)

# ✅ Split Features (X) and Labels (y)
X_train, y_train = train_df.iloc[:, :-1].values, train_df["label"].values
X_test, y_test = test_df.iloc[:, :-1].values, test_df["label"].values

# ✅ Reshape for LSTM (samples, timesteps, features)
X_train = X_train.reshape(X_train.shape[0], 1, X_train.shape[1])
X_test = X_test.reshape(X_test.shape[0], 1, X_test.shape[1])

# ✅ Build Improved LSTM Model
model = Sequential([
    LSTM(128, return_sequences=True, input_shape=(1, X_train.shape[2])),
    BatchNormalization(),
    Dropout(0.3),
    
    LSTM(64, return_sequences=True),
    BatchNormalization(),
    Dropout(0.2),
    
    LSTM(32, return_sequences=False),
    Dense(16, activation="relu"),
    Dense(1, activation="sigmoid")  # Binary Classification
])

model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])

# ✅ Train Model with Callbacks
callbacks = [
    tf.keras.callbacks.ModelCheckpoint("models/cicids_lstm.h5", save_best_only=True, monitor="val_accuracy"),
    tf.keras.callbacks.EarlyStopping(patience=3, monitor="val_loss", restore_best_weights=True)
]

model.fit(X_train, y_train, epochs=15, batch_size=64, validation_data=(X_test, y_test), callbacks=callbacks)

# ✅ Convert to TensorRT (Jetson Nano Optimization)
try:
    import tf2onnx
    import onnx
    import tensorrt as trt

    # Convert to ONNX format
    onnx_model_path = "models/cicids_lstm.onnx"
    model_proto, _ = tf2onnx.convert.from_keras(
        model, 
        input_signature=[tf.TensorSpec([None, 1, X_train.shape[2]], tf.float32, name="lstm_input")], 
        output_path=onnx_model_path
    )

    print("✅ LSTM Model Converted to ONNX:", onnx_model_path)

    # Verify ONNX Model Inputs
    onnx_model = onnx.load(onnx_model_path)
    print("✅ ONNX Model Inputs:", [n.name for n in onnx_model.graph.input])
    print("✅ ONNX Model Outputs:", [n.name for n in onnx_model.graph.output])

    # Convert ONNX to TensorRT (Updated command with correct input name)
    trt_model_path = "models/cicids_lstm_trt.plan"
    os.system(f"trtexec --onnx={onnx_model_path} --saveEngine={trt_model_path} --optShapes=lstm_input:1x1x{X_train.shape[2]}")

    print("✅ TensorRT Model Saved:", trt_model_path)
except Exception as e:
    print(f"⚠️ TensorRT conversion failed: {e}")
