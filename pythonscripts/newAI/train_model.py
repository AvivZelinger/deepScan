# train_model.py

import pandas as pd
from sqlalchemy import create_engine
from scapy.all import rdpcap, UDP, IP
import struct
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from tensorflow.keras import layers, models
import tensorflow as tf
import joblib
import os
import sys

# הגדר את פרטי החיבור ל-MySQL
DB_USER = 'root'
DB_PASSWORD = 'admin'
DB_HOST = 'localhost'
DB_PORT = '3306'
DB_NAME = 'project'

# צור את ה-engine
engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}')

# קרא את הטבלה לתוך DataFrame
protocol_df = pd.read_sql('SELECT * FROM ProtocolSizesAndType', engine)

def parse_pcap(pcap_file, protocol_df):
    """
    מפענח קובץ PCAP ומחלץ נתוני שדות לפי הגדרות הפרוטוקול.
    מחזיר רשימה של רשומות עבור כל שדה עם תכונות ועמודת מטרה.
    """
    packets = rdpcap(pcap_file)
    data = []

    for pkt in packets:
        if UDP in pkt and (pkt[UDP].dport == 10000 or pkt[UDP].sport == 10000):
            try:
                payload = pkt[UDP].payload.load
                offset = 0
                packet_data = {}
                # נעבור על כל שורה בטבלת הפרוטוקול
                for index, row in protocol_df.iterrows():
                    field_name = row['name']
                    field_size = row['size']
                    field_type = row['type']
                    length_field = row['length_field']  # אפשרי שהעמודה אינה קיימת – במקרה זה היא תהיה None

                    # אם field_size שווה ל־0, מדובר בשדה דינמי – יש לקבל את הגודל משדה הגדרה
                    if field_size == 0:
                        if pd.notnull(length_field) and (length_field in packet_data):
                            field_size = int(packet_data[length_field])
                        else:
                            print(f"Cannot determine size for dynamic field '{field_name}' without '{length_field}'")
                            break

                    if offset + field_size > len(payload):
                        print(f"Not enough data for field '{field_name}' in packet.")
                        break

                    field_bytes = payload[offset:offset + field_size]

                    # המרת הבתים לסוג הנתון בהתאם להגדרה
                    if field_type == 'int':
                        value = int.from_bytes(field_bytes, byteorder='big')
                    elif field_type == 'float':
                        value = struct.unpack('!f', field_bytes)[0]
                    elif field_type == 'char':
                        value = field_bytes.decode('utf-8', errors='ignore').strip('\x00')
                    elif field_type == 'bool':
                        value = bool(int.from_bytes(field_bytes, byteorder='big'))
                    else:
                        value = field_bytes.hex()  # עבור סוגים אחרים

                    packet_data[field_name] = value
                    offset += field_size

                    # נרצה להשתמש בסוג השדה כעמודת מטרה (field_type)
                    record = {
                        'field_name': field_name,
                        'size': field_size,
                        'value': value,
                        'field_type': field_type
                    }
                    data.append(record)

            except Exception as e:
                print(f"Error parsing packet: {e}")
                continue

    return data

# הכנת נתונים לאימון
pcap_directory = '/mnt/c/Users/aviv/Desktop/newProject/pythonscripts/newAI/data'
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

# יצירת DataFrame מהנתונים
data_df = pd.DataFrame(all_data)
if data_df.empty:
    print("No data parsed from PCAP files.")
    sys.exit(1)

# טיפול בערכים חסרים
data_df['value'] = data_df['value'].replace('', np.nan)
data_df = data_df.dropna(subset=['value'])

# המרת עמודת 'value' למחרוזת (string) – כדי להבטיח אחידות
data_df['value'] = data_df['value'].astype(str)

# הגדרת תכונות ועמודת מטרה:
# X: features - העמודות 'size' ו-'value'
# y: label - העמודה 'field_type'
X = data_df[['size', 'value']]
y = data_df['field_type']

# קידוד התוויות
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)
joblib.dump(label_encoder, 'label_encoder.joblib')

# הגדרת תכונות מספריות וקטגוריאליות
numeric_features = ['size']
categorical_features = ['value']

numeric_transformer = Pipeline(steps=[
    ('scaler', StandardScaler())
])

categorical_transformer = Pipeline(steps=[
    ('onehot', OneHotEncoder(handle_unknown='ignore'))
])

preprocessor = ColumnTransformer(
    transformers=[
        ('num', numeric_transformer, numeric_features),
        ('cat', categorical_transformer, categorical_features)
    ])

# המרת הנתונים
X_processed = preprocessor.fit_transform(X)
joblib.dump(preprocessor, 'preprocessor.joblib')

# חלוקת הנתונים לסטים לאימון, ולידציה ובדיקה
X_train, X_temp, y_train, y_temp = train_test_split(X_processed, y_encoded, test_size=0.3, random_state=42)
X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42)

# בניית המודל – רשת נוירונים פשוטה
input_dim = X_train.shape[1]
model = models.Sequential([
    layers.Dense(256, activation='relu', input_shape=(input_dim,)),
    layers.Dropout(0.3),
    layers.Dense(128, activation='relu'),
    layers.Dropout(0.3),
    layers.Dense(64, activation='relu'),
    layers.Dense(len(label_encoder.classes_), activation='softmax')
])

model.compile(optimizer='adam',
              loss='sparse_categorical_crossentropy',
              metrics=['accuracy'])

# אימון המודל
history = model.fit(
    X_train, y_train,
    epochs=100,
    batch_size=64,
    validation_data=(X_val, y_val),
    callbacks=[tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)]
)

# הערכת המודל
test_loss, test_acc = model.evaluate(X_test, y_test)
print(f"Test Accuracy: {test_acc}")

# שמירת המודל
model.save('dpi_model.h5')
print("Model saved as 'dpi_model.h5'.")
