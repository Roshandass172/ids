import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.optimizers import Adam
import matplotlib.pyplot as plt

# Load preprocessed data
data = np.load("data/cicids2017_processed.npy")

# Define Autoencoder Model
input_dim = data.shape[1]
input_layer = Input(shape=(input_dim,))
encoded = Dense(32, activation="relu")(input_layer)
encoded = Dense(16, activation="relu")(encoded)
encoded = Dense(8, activation="relu")(encoded)
decoded = Dense(16, activation="relu")(encoded)
decoded = Dense(32, activation="relu")(decoded)
decoded = Dense(input_dim, activation="sigmoid")(decoded)

autoencoder = Model(input_layer, decoded)
autoencoder.compile(optimizer=Adam(learning_rate=0.001), loss="mse")

# Train Model
history = autoencoder.fit(
    data, data, 
    epochs=50, 
    batch_size=64, 
    shuffle=True, 
    validation_split=0.1
)

# Save as TensorFlow Model for TensorRT
autoencoder.save("models/kitsune_trt.plan")
print("✅ Kitsune Autoencoder Trained & Saved!")

# Plot Loss Curve
plt.plot(history.history["loss"], label="Train Loss")
plt.plot(history.history["val_loss"], label="Validation Loss")
plt.xlabel("Epochs")
plt.ylabel("Loss")
plt.legend()
plt.show()
