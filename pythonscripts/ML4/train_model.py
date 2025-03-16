# train_model.py

import os
import sys
import struct
import random
import numpy as np
import pandas as pd
from sqlalchemy import create_engine
from scapy.all import rdpcap, UDP, IP
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from tensorflow.keras import layers, models
import tensorflow as tf
import joblib

##########################################
# MySQL database connection settings
##########################################
DB_USER = 'root'
DB_PASSWORD = 'admin'
DB_HOST = 'localhost'
DB_PORT = '3306'
DB_NAME = 'project'

engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}')

##########################################
# Read protocol definition table
##########################################
# The table now includes: name, size, type, size_field
protocol_df = pd.read_sql('select name,size,type,size_field from ProtocolSizesAndType', engine)
print(protocol_df)
##########################################
# Function: parse_pcap (generic version)
##########################################
def parse_pcap(pcap_file, protocol_df):
    """
    Parses a PCAP file and extracts field data based on protocol definitions.
    For each field:
      - If the fixed size (size) is non-zero, that is used.
      - If size==0 (dynamic field), then:
          If a size_field is specified, its previously parsed value is used;
          Otherwise, the remaining payload length is used.
    Returns a list of records (each is a dict with field info).
    """
    packets = rdpcap(pcap_file)
    data = []

    for pkt in packets:
        if UDP in pkt and (pkt[UDP].dport == 10000 or pkt[UDP].sport == 10000):
            try:
                payload = pkt[UDP].payload.load
                offset = 0
                packet_data = {}
                for index, row in protocol_df.iterrows():
                    field_name = row['name']
                    field_size = row['size']
                    field_type = row['type']
                    size_field_name = row['size_field']  # New column for dynamic size
                    size_defining = None

                    # For dynamic fields (size==0), check if a size_field is defined.
                    if field_size == 0:
                        available_length = len(payload) - offset
                        if pd.notnull(size_field_name) and size_field_name != '':
                            candidate_val = packet_data.get(size_field_name)
                            # print(f"Size field: {size_field_name}, value: {candidate_val}")
                            if candidate_val is not None:
                                try:
                                    field_size = int(candidate_val)
                                except Exception:
                                    field_size = available_length
                            else:
                                field_size = available_length
                            size_defining = size_field_name
                        else:
                            field_size = available_length
                            size_defining = None

                    if offset + field_size > len(payload):
                        print(f"Not enough data for field '{field_name}' in packet.")
                        break

                    field_bytes = payload[offset:offset + field_size]

                    if field_type == 'int':
                        value = int.from_bytes(field_bytes, byteorder='big')
                    elif field_type == 'float':
                        value = struct.unpack('!f', field_bytes)[0]
                    elif field_type == 'char':
                        value = field_bytes.decode('utf-8', errors='ignore').strip('\x00')
                    elif field_type == 'bool':
                        value = bool(int.from_bytes(field_bytes, byteorder='big'))
                    else:
                        value = field_bytes.hex()

                    offset += field_size
                    # Save the value so that it can be used if a later field depends on it.
                    packet_data[field_name] = value

                    record = {
                        'field_name': field_name,
                        'size': field_size,
                        'value': value,
                        'field_type': field_type,
                        'size_defining_field': size_defining
                    }
                    data.append(record)
            except Exception as e:
                print(f"Error parsing packet: {e}")
                continue

    return data

##########################################
# Prepare training data
##########################################
pcap_directory = '/mnt/c/Users/aviv/Desktop/newProject/pythonscripts/ML4/data'
if not os.path.exists(pcap_directory):
    print(f"PCAP directory '{pcap_directory}' does not exist.")
    sys.exit(1)

pcap_files = [os.path.join(pcap_directory, f) for f in os.listdir(pcap_directory) if f.endswith('.pcap')]
all_data = []

for pcap_file in pcap_files:
    print(f"Parsing PCAP file: {pcap_file}")
    parsed_data = parse_pcap(pcap_file, protocol_df)
    if parsed_data:
        all_data.extend(parsed_data)

data_df = pd.DataFrame(all_data)
if data_df.empty:
    print("No data parsed from PCAP files.")
    sys.exit(1)

# --- New Feature Engineering ---
# Instead of simply converting 'value' to string, we create two new features:
# 1. value_numeric: for 'int' or 'float' fields, convert value to float (else 0)
# 2. text_length: for non-numeric fields, record the length of the text (else 0)
def extract_numeric(val, ftype):
    if ftype in ['int', 'float']:
        try:
            return float(val)
        except:
            return 0.0
    return 0.0

def extract_text_length(val, ftype):
    if ftype in ['int', 'float']:
        return 0
    # Convert value to string and return its length (strip any whitespace)
    return len(str(val).strip())

data_df['value_numeric'] = data_df.apply(lambda row: extract_numeric(row['value'], row['field_type']), axis=1)
data_df['text_length'] = data_df.apply(lambda row: extract_text_length(row['value'], row['field_type']), axis=1)

# We'll use these three features: size, value_numeric, and text_length
X = data_df[['size', 'value_numeric', 'text_length']]
y = data_df['field_type']

# Encode the target label
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)
joblib.dump(label_encoder, 'label_encoder.joblib')

# Since all our features are numeric now, we use a StandardScaler
preprocessor = StandardScaler()
X_processed = preprocessor.fit_transform(X)
joblib.dump(preprocessor, 'preprocessor.joblib')

##########################################
# Split the data into train, validation, and test sets
##########################################
X_train, X_temp, y_train, y_temp = train_test_split(X_processed, y_encoded, test_size=0.3, random_state=42)
X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42)

##########################################
# Build and train the model
##########################################
input_dim = X_train.shape[1]
model = models.Sequential([
    # Instead of passing input_dim directly, we use an Input layer
    layers.Input(shape=(input_dim,)),
    layers.Dense(256, activation='relu'),
    layers.Dropout(0.3),
    layers.Dense(128, activation='relu'),
    layers.Dropout(0.3),
    layers.Dense(64, activation='relu'),
    layers.Dense(len(label_encoder.classes_), activation='softmax')
])

model.compile(optimizer='adam',
              loss='sparse_categorical_crossentropy',
              metrics=['accuracy'])

history = model.fit(
    X_train, y_train,
    epochs=10,
    batch_size=8192,
    validation_data=(X_val, y_val),
    callbacks=[tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)]
)

test_loss, test_acc = model.evaluate(X_test, y_test)
print(f"Test Accuracy: {test_acc}")
print(f"Test Loss: {test_loss}")
print("Model training completed.")

# Save the model (you can change the format if desired)
model.save('dpi_model.h5')
print("Model saved as 'dpi_model.h5'.")