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

##########################################
# הגדרות חיבור למסד הנתונים (MySQL)
##########################################
DB_USER = 'root'
DB_PASSWORD = 'admin'
DB_HOST = 'localhost'
DB_PORT = '3306'
DB_NAME = 'project'

# יצירת engine
engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}')

##########################################
# קריאה לטבלת הפרוטוקול
##########################################
# טבלת ProtocolSizesAndType צריכה לכלול את העמודות:
#   - name (VARCHAR)
#   - size (INT)
#   - type (VARCHAR)
#
# בשיטה זו אין עמודת length_field.
protocol_df = pd.read_sql('SELECT * FROM Protocol3Definition', engine)

##########################################
# פונקציה: parse_pcap
##########################################
def parse_pcap(pcap_file, protocol_df):
    """
    מפענח קובץ PCAP ומחלץ נתונים לפי הגדרות הפרוטוקול מהטבלה.
    אם שדה מוגדר עם size=0, מניחים שמדובר בשדה דינמי וניקרא את כל שאר ה-Payload.
    מחזיר רשימה של רשומות עבור כל שדה (לצורך אימון המודל).
    """
    packets = rdpcap(pcap_file)
    data = []  # רשימת רשומות לכל שדה

    for pkt in packets:
        if UDP in pkt and (pkt[UDP].dport == 10000 or pkt[UDP].sport == 10000):
            try:
                payload = pkt[UDP].payload.load
                offset = 0
                # נעבור על כל השדות כפי שמוגדרים בטבלה
                for index, row in protocol_df.iterrows():
                    field_name = row['name']
                    field_size = row['size']
                    field_type = row['type']

                    # אם השדה הדינמי (size == 0) – נקרא את כל שאר ה-Payload כערך לשדה
                    if field_size == 0:
                        field_size = len(payload) - offset
                        if field_size <= 0:
                            break

                    if offset + field_size > len(payload):
                        print(f"Not enough data for field '{field_name}' in packet.")
                        break

                    field_bytes = payload[offset:offset + field_size]

                    # המרת הבתים לסוג הנתון המתאים
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

                    # רשומה: כל רשומת שדה תכלול את שם השדה, הגודל, הערך וסוג השדה (מהטבלה)
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

##########################################
# שלבים: איחוד נתונים, טיפול בערכים חסרים והמרת הערכים
##########################################

# ספריית PCAP – נניח שממוקמת בספריה 'pcaps/'
pcap_directory = '/mnt/c/Users/aviv/Desktop/newProject/pythonscripts/newAi2/data3'
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

# טיפול בערכים חסרים – נניח שעבור העמודה 'value' נרצה להסיר שורות ריקות
data_df['value'] = data_df['value'].replace('', np.nan)
data_df = data_df.dropna(subset=['value'])

# המרת עמודת 'value' למחרוזת (string) – חשוב ל-OneHotEncoder
data_df['value'] = data_df['value'].astype(str)

##########################################
# הגדרת הקלט לעבודה עם המודל
##########################################
# Features: 'size' ו-'value'
# Label: 'field_type'
X = data_df[['size', 'value']]
y = data_df['field_type']

# קידוד התוויות (Label Encoding)
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)
joblib.dump(label_encoder, 'label_encoder.joblib')

# הגדרת עמודות מסוימות כערכים מספריים וקטגוריאליים
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

# טרנספורמציית הנתונים
X_processed = preprocessor.fit_transform(X)
joblib.dump(preprocessor, 'preprocessor.joblib')

##########################################
# חלוקת הנתונים
##########################################
X_train, X_temp, y_train, y_temp = train_test_split(X_processed, y_encoded, test_size=0.3, random_state=42)
X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42)

##########################################
# בניית ואימון המודל
##########################################
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

history = model.fit(
    X_train, y_train,
    epochs=100,
    batch_size=64,
    validation_data=(X_val, y_val),
    callbacks=[tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=25, restore_best_weights=True)]
)

test_loss, test_acc = model.evaluate(X_test, y_test)
print(f"Test Accuracy: {test_acc}")
print(f"Test Loss: {test_loss}")

# שמירת המודל
model.save('dpi_model.h5')
print("Model saved as 'dpi_model.h5'.")