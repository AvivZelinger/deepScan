# generate_dpi.py

import pandas as pd
from sqlalchemy import create_engine
from scapy.all import rdpcap, UDP, IP
import struct
import numpy as np
from collections import defaultdict
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.models import load_model
import tensorflow as tf
import warnings
import joblib
import os
import sys
import json

# Define the custom JSON encoder
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyEncoder, self).default(obj)


# import cryptography
##########################################
# הגדרות חיבור למסד הנתונים (MySQL)
##########################################
DB_USER = 'root'
DB_PASSWORD = 'admin'
DB_HOST = 'localhost'
DB_PORT = '3306'
DB_NAME = 'project'

engine = create_engine(f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}')

##########################################
# קריאה לטבלת הפרוטוקול
##########################################
# טבלת ProtocolSizesAndType אמורה לכלול את העמודות: name, size, type
protocol_df = pd.read_sql('SELECT * FROM ProtocolSizesAndType', engine) #ProtocolSizesAndType Protocol4Definition

##########################################
# פונקציה: parse_pcap (גרסה גנרית)
##########################################
def parse_pcap(pcap_file, protocol_df):
    """
    מפענח קובץ PCAP ומחלץ נתוני שדות לפי הגדרות הפרוטוקול מהטבלה.
    
    עבור כל שדה, אם הערך של "size" הוא 0 (כלומר, מדובר בשדה דינמי):
      - מחשבים את האורך הזמין: available_length = len(payload) - offset.
      - סורקים את השדות שכבר נקלטו (ב־packet_data) ומחפשים שדה שערכו תואם בדיוק ל-available_length.
      - אם נמצא שדה כזה, משתמשים בערכו כגודל השדה הדינמי ומעדכנים את המשתנה size_defining_field לשם השדה.
      - אחרת, אם לא נמצא, מניחים שהגודל הוא כל מה שנותר ב־payload.
    
    הפונקציה מחזירה רשימה של רשומות (מילונים) עבור כל שדה, כאשר כל רשומה כוללת:
      - field_name
      - size
      - value
      - field_type
      - size_defining_field
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
                    size_defining = None  # אתחול המשתנה

                    # טיפול בשדה דינמי – אם field_size == 0
                    if field_size == 0:
                        available_length = len(payload) - offset
                        # נסיון לזהות בין השדות הקודמים (ב־packet_data) שדה שערכו תואם בדיוק ל-available_length
                        candidate = None
                        for key, val in packet_data.items():
                            try:
                                if int(val) == available_length:
                                    candidate = key
                                    break
                            except:
                                continue
                        if candidate is not None:
                            field_size = int(packet_data[candidate])
                            size_defining = candidate
                        else:
                            # אם לא נמצא, נניח שהגודל הוא כל מה שנותר
                            field_size = available_length
                            size_defining = None

                    if offset + field_size > len(payload):
                        # print(f"Not enough data for field '{field_name}' in packet.")
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
                    # שמירת הערך ב-packet_data, כך ששדות דינמיים שיבואו בהמשך (אם יהיו) יוכלו להתבסס עליו
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
# פונקציה: preprocess_field_data
##########################################
def preprocess_field_data(field_records, preprocessor):
    """
    ממיר ומעבד נתוני שדה (רשימה של מילונים עם 'size' ו-'value')
    ומחזיר מטריצת תכונות מעובדת.
    """
    df = pd.DataFrame(field_records)
    if df.empty:
        return None

    # המרת הערך למחרוזת כדי להבטיח אחידות
    df['value'] = df['value'].astype(str)
    df['value'] = df['value'].replace('', np.nan)
    df = df.dropna(subset=['value'])

    X_processed = preprocessor.transform(df[['size', 'value']])
    return X_processed

##########################################
# פונקציה: generate_dpi
##########################################
def generate_dpi(endpoints, model, preprocessor, label_encoder):
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

            # חישוב min_value ו-max_value בהתאם לסוג השדה
            first_value = values[0]
            if isinstance(first_value, (int, float)):
                min_value = min(values)
                max_value = max(values)
            elif first_value.lower() in ['true', 'false']:
                min_value = False
                max_value = True
            else:
                min_value = None
                max_value = None

            # בדיקת שדה הגדרת גודל (size_defining_field)
            size_defining_field = None
            for field in packets[0]:
                if field['field_name'] == field_name and field['size_defining_field']:
                    size_defining_field = field['size_defining_field']
                    break

            # טרנספורמציית הנתונים
            field_data = [{'size': s['size'], 'value': s['value']} for s in stats]
            X = preprocess_field_data(field_data, preprocessor)
            if X is None:
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
    if len(sys.argv) != 3:
        print(json.dumps({'error': 'Usage: python generate_dpi.py path_to_pcap_file.pcap Protocol_name'}))
        sys.exit(1)

    pcap_file = sys.argv[1]
    if not os.path.exists(pcap_file):
        print(json.dumps({'error': f'PCAP file {pcap_file} does not exist.'}))
        sys.exit(1)

    protocol_name = sys.argv[2]
    

    # טוען את המודל, ה-preprocessor וה-Label Encoder
    try:
        model = load_model('/mnt/c/Users/aviv/Desktop/newProject/dpi_model.h5')
    except Exception as e:
        print(json.dumps({'error': f'Error loading model: {e}'}))
        sys.exit(1)

    try:
        preprocessor = joblib.load('/mnt/c/Users/aviv/Desktop/newProject/preprocessor.joblib')
    except Exception as e:
        print(json.dumps({'error': f'Error loading preprocessor: {e}'}))
        sys.exit(1)

    try:
        label_encoder = joblib.load('/mnt/c/Users/aviv/Desktop/newProject/label_encoder.joblib')
    except Exception as e:
        print(json.dumps({'error': f'Error loading label encoder: {e}'}))
        sys.exit(1)

    print(f"Parsing PCAP file: {pcap_file}")
    parsed_data = parse_pcap(pcap_file, protocol_df)
    if not parsed_data:
        print(json.dumps({'error': 'No valid data parsed from PCAP file.'}))
        sys.exit(1)

    # ארגון הנתונים לפי כתובת ה-IP
    endpoints = defaultdict(list)
    current_endpoint = None
    for record in parsed_data:
        field_name = record['field_name']
        value = record['value']
    #     if field_name == 'start_flag':
    #         # זיהוי התחלת פקטה – הגדרת כתובת ה-IP
    #         # נניח שכתובת ה-IP כבר ידועה מה-Pcap
    #         # כאן, נשתמש בכתובת ה-IP של הפקטה (צריך להיות מוגדר במידע של הפונקציה parse_pcap)
    #         # כדי לשמור על הפשטות, נעבור על כל הפקטות מחדש
    #         pass  # ניתן להרחיב אם יש צורך
    #     # הכנסה ל-endpoint בהתאם לכתובת ה-IP
    #     # כאן נשתמש במידע הכללי על כל פקטה כפי שנקלט קודם
    #     # נעשה מחדש את הפונקציה parse_pcap כדי לארגן לפי IP
    #     # לשם זה, נשנה מעט את הפונקציה parse_pcap או נשתמש בפונקציה אחרת
    # # במקום זאת, נעדכן parse_pcap כדי להחזיר נתונים מאורגנים לפי IP

    # עדכון parse_pcap כדי להחזיר נתונים מאורגנים לפי IP
    def parse_pcap_with_ip(pcap_file, protocol_df):
        """
        דומה לפונקציית parse_pcap, אבל מחזירה מילון מאורגן לפי כתובת ה-IP.
        """
        packets = rdpcap(pcap_file)
        data = defaultdict(list)

        for pkt in packets:
            if UDP in pkt and (pkt[UDP].dport == 10000 or pkt[UDP].sport == 10000):
                try:
                    src_ip = pkt[IP].src if pkt[UDP].dport == 10000 else pkt[IP].dst
                    payload = pkt[UDP].payload.load
                    offset = 0
                    packet_data = {}
                    records = []
                    for index, row in protocol_df.iterrows():
                        field_name = row['name']
                        field_size = row['size']
                        field_type = row['type']
                        size_defining = None  # אתחול המשתנה
                        #print(f'the offset is: {offset}')
                        # טיפול בשדה דינמי – אם field_size == 0
                        if field_size == 0:
                            # Calculate remaining fixed size required for fields defined after the current one
                            remaining_fixed_size = 0
                            for j in range(index + 1, len(protocol_df)):
                                next_field_size = protocol_df.iloc[j]['size']
                                if next_field_size != 0:
                                    remaining_fixed_size += next_field_size
                            dynamic_field_size = len(payload) - offset - remaining_fixed_size
                            #print(len(payload))
                            # נסיון לזהות בין השדות הקודמים (ב־packet_data) שדה שערכו תואם בדיוק ל-dynamic_field_size
                            candidate = None
                            for key, val in packet_data.items():
                                try:
                                    #print(f'{key}=> {val} || dynamic_field_size=> {dynamic_field_size}')
                                    if int(val) == dynamic_field_size:
                                        candidate = key
                                        break
                                except:
                                    continue
                            if candidate is not None:
                                field_size = int(packet_data[candidate])
                                size_defining = candidate
                            else:
                                # אם לא נמצא, נניח שהגודל הוא כל מה שנותר לאחר חיסור השדות הקבועים
                                field_size = dynamic_field_size
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
                        # שמירת הערך ב-packet_data, כך ששדות דינמיים שיבואו בהמשך (אם יהיו) יוכלו להתבסס עליו
                        packet_data[field_name] = value

                        record = {
                            'field_name': field_name,
                            'size': field_size,
                            'value': value,
                            'field_type': field_type,
                            'size_defining_field': size_defining
                        }
                        records.append(record)

                    if records:
                        data[src_ip].append(records)
                except Exception as e:
                    print(f"Error parsing packet: {e}")
                    continue

        return data

    # השתמש בפונקציה המעודכנת
    endpoints = parse_pcap_with_ip(pcap_file, protocol_df)
    if not endpoints:
        print(json.dumps({'error': 'No valid packets found in PCAP file.'}))
        sys.exit(1)

    print("Generating DPI...")
    dpi = generate_dpi(endpoints, model, preprocessor, label_encoder)
    final_result = {
        'protocol': protocol_name,  # ניתן להחליף אם יש צורך
        'dpi': dpi
    }



    # שמירת הפלט לקובץ JSON
    output_file = "dpi_output.json"
    with open(output_file, "w", encoding='utf-8') as f:
        json.dump(final_result, f, ensure_ascii=False, indent=4, cls=NumpyEncoder)
    print(f"DPI output saved to {output_file}")
    
if __name__ == '__main__':
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 
    tf.get_logger().setLevel('ERROR')  # Set TensorFlow logger to only show errors

    warnings.filterwarnings('ignore')  # Ignore all Python warnings

    main()
