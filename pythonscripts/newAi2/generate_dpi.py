# generate_dpi.py

import pandas as pd
from sqlalchemy import create_engine
from scapy.all import rdpcap, UDP, IP
import struct
import numpy as np
from tensorflow.keras.models import load_model
import joblib
import sys
import os
import json
from collections import defaultdict

# הגדר את פרטי החיבור ל-MySQL
DB_USER = 'root'
DB_PASSWORD = 'admin'
DB_HOST = 'localhost'
DB_PORT = '3306'
DB_NAME = 'project'

# צור את ה-engine
engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}')

def get_protocol_table(engine):
    """
    קורא את טבלת ProtocolSizesAndType מ-MySQL.
    """
    protocol_df = pd.read_sql('SELECT * FROM Protocol3Definition', engine)
    return protocol_df

def parse_pcap(pcap_file, protocol_df):
    """
    מפענח קובץ PCAP ומקבץ פקטות לפי כתובת ה-IP של ה-endpoint.
    
    עבור כל שדה:
      - אם ערך "size" שווה ל-0, מניחים שמדובר בשדה דינמי – וניקרא את כל שאר ה-Payload.
    
    מחזיר מילון, כאשר המפתחות הם כתובות ה-IP והערכים הם רשימות של רשומות שדה.
    """
    packets = rdpcap(pcap_file)
    endpoints = defaultdict(list)

    for pkt in packets:
        if UDP in pkt and (pkt[UDP].dport == 10000 or pkt[UDP].sport == 10000):
            try:
                # קביעת כתובת ה-IP לפי כיוון התקשורת
                if pkt[UDP].dport == 10000:
                    endpoint_ip = pkt[IP].src
                else:
                    endpoint_ip = pkt[IP].dst

                payload = pkt[UDP].payload.load
                offset = 0
                field_records = []
                # מעבר על הגדרות השדות לפי הטבלה; אין שימוש בעמודת length_field
                for index, row in protocol_df.iterrows():
                    field_name = row['name']
                    field_size = row['size']
                    field_type = row['type']

                    # אם גודל השדה שווה ל-0 – מניחים שמדובר בשדה דינמי (שדה אחרון)
                    if field_size == 0:
                        field_size = len(payload) - offset
                        if field_size <= 0:
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
                        value = field_bytes.hex()

                    offset += field_size

                    record = {
                        'field_name': field_name,
                        'size': field_size,
                        'value': value
                    }
                    field_records.append(record)
                    
                if field_records:
                    endpoints[endpoint_ip].append(field_records)

            except Exception as e:
                print(f"Error parsing packet: {e}")
                continue

    return endpoints

def preprocess_field_data(field_records, preprocessor):
    """
    ממיר ומעבד נתוני שדה (רשימה של מילונים עם 'size' ו-'value')
    ומחזיר DataFrame מעובד לאחר טרנספורמציה.
    """
    df = pd.DataFrame(field_records)
    if df.empty:
        return df

    # המרת הערך למחרוזת כדי להבטיח אחידות
    df['value'] = df['value'].astype(str)
    df['value'] = df['value'].replace('', np.nan)
    df = df.dropna(subset=['value'])

    X_processed = preprocessor.transform(df[['size', 'value']])
    return X_processed

def generate_dpi(endpoints, protocol_df, model, preprocessor, label_encoder):
    """
    מייצר DPI לכל endpoint.
    מחזיר מילון עם DPI לכל כתובת IP.
    """
    dpi_result = {}

    for endpoint_ip, packets in endpoints.items():
        field_stats = defaultdict(list)
        # איסוף כל הרשומות עבור כל endpoint
        for packet in packets:
            for field in packet:
                field_name = field['field_name']
                size = field['size']
                value = field['value']
                field_stats[field_name].append({'size': size, 'value': value})

        dpi = {}
        for field_name, stats in field_stats.items():
            sizes = [s['size'] for s in stats]
            values = [s['value'] for s in stats]

            is_dynamic_array = len(set(sizes)) > 1
            min_size = min(sizes)
            max_size = max(sizes)

            first_value = values[0]
            if isinstance(first_value, (int, float)):
                min_value = min(values)
                max_value = max(values)
            else:
                min_value = None
                max_value = None

            size_defining_field = None
            for other_field, other_stats in field_stats.items():
                other_values = [s['value'] for s in other_stats]
                if other_values == sizes and other_field != field_name:
                    size_defining_field = other_field
                    break

            field_data = [{'size': s['size'], 'value': s['value']} for s in stats]
            X = preprocess_field_data(field_data, preprocessor)
            if X.shape[0] == 0:
                field_type = 'unknown'
            else:
                predictions = model.predict(X)
                predicted_labels = label_encoder.inverse_transform(np.argmax(predictions, axis=1))
                field_type = pd.Series(predicted_labels).mode()[0]

            dpi[field_name] = {
                'is_dynamic_array': is_dynamic_array,
                'min_size': min_size,
                'max_size': max_size,
                'min_value': min_value,
                'max_value': max_value,
                'size_defining_field': size_defining_field,
                'field_type': field_type
            }

        dpi_result[endpoint_ip] = dpi

    return dpi_result

def main():
    if len(sys.argv) != 2:
        print(json.dumps({'error': 'Usage: python generate_dpi.py path_to_pcap_file.pcap'}))
        sys.exit(1)

    pcap_file = sys.argv[1]
    if not os.path.exists(pcap_file):
        print(json.dumps({'error': f'PCAP file {pcap_file} does not exist.'}))
        sys.exit(1)

    # טוען את המודל, ה-preprocessor וה-Label Encoder
    model = load_model('dpi_model.h5')
    preprocessor = joblib.load('preprocessor.joblib')
    label_encoder = joblib.load('label_encoder.joblib')

    protocol_df = get_protocol_table(engine)

    print(f"Parsing PCAP file: {pcap_file}")
    endpoints = parse_pcap(pcap_file, protocol_df)
    if not endpoints:
        print(json.dumps({'error': 'No valid packets found in PCAP file.'}))
        sys.exit(1)

    print("Generating DPI...")
    dpi = generate_dpi(endpoints, protocol_df, model, preprocessor, label_encoder)
    final_result = {
        'protocol': 'CustomProtocol',
        'dpi': dpi
    }

    # שמירת הפלט לקובץ JSON
    output_file = "dpi_output2.json"
    with open(output_file, "w", encoding='utf-8') as f:
        json.dump(final_result, f, ensure_ascii=False, indent=4)
    print(f"DPI output saved to {output_file}")

if __name__ == '__main__':
    main()
