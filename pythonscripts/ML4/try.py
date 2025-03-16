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

# Define a custom JSON encoder for NumPy types.
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyEncoder, self).default(obj)

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
protocol_df = pd.read_sql('Select name, size, type, size_field from ProtocolSizesAndType', engine)
if 'is_bitfield' not in protocol_df.columns:
    protocol_df['is_bitfield'] = False

##########################################
# Helper function: count_bitfields
##########################################
def count_bitfields(field_bytes):
    """
    Counts the number of 1 bits in the given field bytes.
    """
    return bin(int.from_bytes(field_bytes, byteorder='big')).count('1')

##########################################
# Function: parse_pcap (generic version)
##########################################
def parse_pcap(pcap_file, protocol_df):
    """
    Parses a PCAP file and extracts field data based on protocol definitions.
    Returns a list of records with field details (including bitfield info).
    For fields that are not bitfields, bitfields_count is set to None.
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
                    size_field_name = row['size_field']
                    is_bitfield = bool(row.get('is_bitfield', False))
                    size_defining = None

                    if field_size == 0:
                        available_length = len(payload) - offset
                        if pd.notnull(size_field_name) and size_field_name != '':
                            candidate_val = packet_data.get(size_field_name)
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

                    if is_bitfield or field_type == 'bitfield':
                        bit_vector = [int(x) for x in format(
                            int.from_bytes(field_bytes, byteorder='big'),
                            '0{}b'.format(field_size * 8)
                        )]
                        bitfields_count = sum(bit_vector)
                        value = bit_vector
                    else:
                        bitfields_count = None  # Set to null for non-bitfield types.
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
                    packet_data[field_name] = value

                    record = {
                        'field_name': field_name,
                        'size': field_size,
                        'value': value,
                        'field_type': field_type,
                        'size_defining_field': size_defining,
                        'bitfields_count': bitfields_count
                    }
                    if is_bitfield or field_type == 'bitfield':
                        record['bit_vector'] = bit_vector
                    data.append(record)
            except Exception as e:
                print(f"Error parsing packet: {e}")
                continue

    return data

##########################################
# Function: preprocess_field_data
##########################################
def preprocess_field_data(field_records, preprocessor):
    """
    Processes a list of field records to produce a feature matrix for model prediction.
    Computes:
      - value_numeric: For int/float fields or bitfields (using the bit count).
      - text_length: For non-numeric fields (or the length of the bit vector for bitfields).
    """
    df = pd.DataFrame(field_records)
    if df.empty:
        return None

    df['value'] = df['value'].astype(str)
    df['value'] = df['value'].replace('', np.nan)
    df = df.dropna(subset=['value'])

    def extract_numeric(val, ftype):
        if ftype in ['int', 'float']:
            try:
                return float(val)
            except:
                return 0.0
        elif ftype == 'bitfield':
            if isinstance(val, list):
                return float(sum(val))
            return 0.0
        return 0.0

    def extract_text_length(val, ftype):
        if ftype in ['int', 'float']:
            return 0
        elif ftype == 'bitfield':
            if isinstance(val, list):
                return len(val)
            return 0
        return len(val.strip())

    df['value_numeric'] = df.apply(lambda row: extract_numeric(row['value'], row['field_type']), axis=1)
    df['text_length'] = df.apply(lambda row: extract_text_length(row['value'], row['field_type']), axis=1)

    X_processed = preprocessor.transform(df[['size', 'value_numeric', 'text_length']])
    return X_processed

##########################################
# Function: generate_dpi
##########################################
def generate_dpi(endpoints, model, preprocessor, label_encoder):
    """
    Generates DPI information for each endpoint.
    Returns a dictionary keyed by IP address with DPI details for each field.
    For bitfield fields, the aggregated bitfields_count (rounded to an integer) is included;
    for other fields, bitfields_count is set to null.
    """
    dpi_result = {}

    for endpoint_ip, packets in endpoints.items():
        field_stats = defaultdict(list)
        for packet in packets:
            for field in packet:
                field_name = field['field_name']
                size = field['size']
                value = field['value']
                bitfields_count_record = field.get('bitfields_count', None)
                field_stats[field_name].append({
                    'size': size,
                    'value': value,
                    'field_type': field['field_type'],
                    'bitfields_count': bitfields_count_record,
                    'bit_vector': field.get('bit_vector', None)
                })

        dpi = {}
        for field_name, stats in field_stats.items():
            sizes = [s['size'] for s in stats]
            values = [s['value'] for s in stats]
            is_dynamic_array = len(set(sizes)) > 1
            min_size = min(sizes)
            max_size = max(sizes)

            first_value = values[0]
            if isinstance(first_value, list):  # Bitfield: value is a bit vector.
                numeric_values = [sum(v) if isinstance(v, list) else 0 for v in values]
                min_value = min(numeric_values)
                max_value = max(numeric_values)
                # Compute the average and round to an integer.
                bitfields_count = int(round(sum(numeric_values) / len(numeric_values)))
            elif isinstance(first_value, (int, float)):
                min_value = min(values)
                max_value = max(values)
                bitfields_count = None
            elif first_value.lower() in ['true', 'false']:
                min_value = False
                max_value = True
                bitfields_count = None
            else:
                min_value = None
                max_value = None
                bitfields_count = None

            size_defining_field = None
            for field in packets[0]:
                if field['field_name'] == field_name and field['size_defining_field']:
                    size_defining_field = field['size_defining_field']
                    break

            field_data = [{
                'size': s['size'],
                'value': s['value'],
                'field_type': s['field_type']
            } for s in stats]

            X = preprocess_field_data(field_data, preprocessor)
            if X is None:
                field_type_pred = 'unknown'
            else:
                predictions = model.predict(X)
                predicted_indices = predictions.argmax(axis=1)
                predicted_labels = label_encoder.inverse_transform(predicted_indices)
                confidences = np.max(predictions, axis=1)
                accuracy = float(np.mean(confidences))
                print(f"Field: {field_name}, Accuracy: {accuracy}")
                field_type_pred = pd.Series(predicted_labels).mode()[0]

            field_dpi = {
                'is_dynamic_array': is_dynamic_array,
                'min_size': min_size,
                'max_size': max_size,
                'min_value': min_value,
                'max_value': max_value,
                'size_defining_field': size_defining_field,
                'field_type': field_type_pred
            }

            # For bitfields, include the aggregated bitfields_count; for others, set to null.
            if isinstance(first_value, list):
                field_dpi['bitfields_count'] = bitfields_count
            else:
                field_dpi['bitfields_count'] = None

            dpi[field_name] = field_dpi

        dpi_result[endpoint_ip] = dpi

    return dpi_result

##########################################
# Updated function: parse_pcap_with_ip
##########################################
def parse_pcap_with_ip(pcap_file, protocol_df):
    """
    Parses a PCAP file and organizes the parsed records by IP address.
    """
    packets = rdpcap(pcap_file)
    print(f"Total packets: {len(packets)}")
    data = defaultdict(list)

    for pkt in packets:
        # print(f"Packet: {pkt.summary()}")
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
                    size_field_name = row['size_field']
                    is_bitfield = bool(row.get('is_bitfield', False))
                    size_defining = None

                    if field_size == 0:
                        remaining_fixed_size = 0
                        for j in range(index + 1, len(protocol_df)):
                            next_field_size = protocol_df.iloc[j]['size']
                            if next_field_size != 0:
                                remaining_fixed_size += next_field_size
                        dynamic_field_size = len(payload) - offset - remaining_fixed_size
                        if pd.notnull(size_field_name) and size_field_name != '':
                            candidate_val = packet_data.get(size_field_name)
                            print(f"Size field: {size_field_name}, value: {candidate_val},{packet_data.get(size_field_name)}")
                            if candidate_val is not None:
                                try:
                                    field_size = int(candidate_val)
                                except:
                                    field_size = dynamic_field_size
                            else:
                                field_size = dynamic_field_size
                            size_defining = size_field_name
                        else:
                            field_size = dynamic_field_size
                            size_defining = None

                    if offset + field_size > len(payload):
                        print(f"Not enough data for field '{field_name}' in packet.")
                        break

                    field_bytes = payload[offset:offset + field_size]

                    if is_bitfield or field_type == 'bitfield':
                        bit_vector = [int(x) for x in format(
                            int.from_bytes(field_bytes, byteorder='big'),
                            '0{}b'.format(field_size * 8)
                        )]
                        bitfields_count = sum(bit_vector)
                        value = bit_vector
                    else:
                        bitfields_count = None
                        if field_type == 'int':
                            value = int.from_bytes(field_bytes, byteorder='big')
                        elif field_type == 'float':
                            value = struct.unpack('!f', field_bytes)[0]
                        elif field_type == 'char':
                            value = field_bytes.decode('utf-8', errors='ignore').strip('\x00')
                        elif field_type == 'bool':
                            value = bool(int.from_bytes(field_bytes, byteorder='big'))
                        elif field_type == 'long':
                            value = int.from_bytes(field_bytes, byteorder='big')
                        elif field_type == 'double':
                            value = struct.unpack('!d', field_bytes)[0]
                        elif field_type == 'short':
                            value = int.from_bytes(field_bytes, byteorder='big', signed=True)
                        else:
                            value = field_bytes.hex()

                    offset += field_size
                    packet_data[field_name] = value

                    record = {
                        'field_name': field_name,
                        'size': field_size,
                        'value': value,
                        'field_type': field_type,
                        'size_defining_field': size_defining,
                        'bitfields_count': bitfields_count
                    }
                    if is_bitfield or field_type == 'bitfield':
                        record['bit_vector'] = bit_vector
                    records.append(record)

                if records:
                    # print(f"Packet data: {packet_data}")
                    data[src_ip].append(records)
            except Exception as e:
                print(f"Error parsing packet: {e}")
                continue
    # print(f"Total endpoints: {len(data)}")
    return data

def main():
    if len(sys.argv) != 3:
        print(json.dumps({'error': 'Usage: python generate_dpi.py path_to_pcap_file.pcap Protocol_name'}))
        sys.exit(1)

    pcap_file = sys.argv[1]
    if not os.path.exists(pcap_file):
        print(json.dumps({'error': f'PCAP file {pcap_file} does not exist.'}))
        sys.exit(1)

    protocol_name = sys.argv[2]
    
    # Load the trained model, preprocessor, and label encoder.
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
    endpoints = parse_pcap_with_ip(pcap_file, protocol_df)
    if not endpoints:
        print(json.dumps({'error': 'No valid packets found in PCAP file.'}))
        sys.exit(1)

    print("Generating DPI...")
    dpi = generate_dpi(endpoints, model, preprocessor, label_encoder)
    final_result = {
        'protocol': protocol_name,
        'dpi': dpi
    }

    output_file = "dpi_output.json"
    with open(output_file, "w", encoding='utf-8') as f:
        json.dump(final_result, f, ensure_ascii=False, indent=4, cls=NumpyEncoder)
    print(f"DPI output saved to {output_file}")

if __name__ == '__main__':
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
    tf.get_logger().setLevel('ERROR')
    warnings.filterwarnings('ignore')
    main()
