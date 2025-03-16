import pandas as pd
import numpy as np
from scapy.all import rdpcap
import mysql.connector
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from typing import List, Dict, Tuple
import json

class ProtocolDPIBuilder:
    def __init__(self, db_config: Dict):
        self.db_config = db_config
        self.protocol_fields = None
        self.model = RandomForestClassifier(n_estimators=100)
        
    def load_protocol_structure(self) -> pd.DataFrame:
        connection = mysql.connector.connect(**self.db_config)
        query = "SELECT * FROM ProtocolSizesAndType"
        protocol_fields = pd.read_sql(query, connection)
        connection.close()
        self.protocol_fields = protocol_fields
        return protocol_fields

    def _convert_to_scalar(self, value) -> float:
        """Convert various types to scalar values for ML processing."""
        if isinstance(value, (int, float)):
            return float(value)
        elif isinstance(value, (list, tuple)):
            return float(len(value))
        elif isinstance(value, dict):
            return float(len(value))
        elif isinstance(value, str):
            return float(len(value))
        elif isinstance(value, bytes):
            return float(len(value))
        elif isinstance(value, np.ndarray):
            return float(value.size)
        else:
            return 0.0

    def _analyze_payload(self, payload: bytes) -> Dict:
        if not payload:
            return {}
            
        features = {}
        offset = 0
        
        for _, row in self.protocol_fields.iterrows():
            try:
                field_name = row['name']
                field_size = row['size']
                field_type = row['type']
                
                if offset + field_size > len(payload):
                    break
                
                field_data = payload[offset:offset + field_size]
                if not field_data:
                    continue
                
                field_values = [int(b) for b in field_data]
                
                if field_values:
                    # Convert all statistical measures to scalar values
                    features[f"{field_name}_mean"] = float(np.mean(field_values))
                    features[f"{field_name}_std"] = float(np.std(field_values)) if len(field_values) > 1 else 0.0
                    features[f"{field_name}_min"] = float(min(field_values))
                    features[f"{field_name}_max"] = float(max(field_values))
                    
                    # Pattern detection
                    if len(field_values) > 1:
                        series = pd.Series(field_values)
                        autocorr = series.autocorr(lag=1)
                        features[f"{field_name}_repeated_patterns"] = float(autocorr) if not np.isnan(autocorr) else 0.0
                    else:
                        features[f"{field_name}_repeated_patterns"] = 0.0
                    
                    # Type-specific features
                    if field_type == 'int':
                        value_range = self._analyze_int_range(field_data)
                        features[f"{field_name}_range_min"] = float(value_range[0])
                        features[f"{field_name}_range_max"] = float(value_range[1])
                    elif field_type == 'char':
                        char_dist = self._analyze_char_distribution(field_data)
                        features[f"{field_name}_unique_chars"] = float(len(char_dist))
                
                offset += field_size
                
            except Exception as e:
                print(f"Error processing field {field_name}: {e}")
                continue
                
        return features

    def _analyze_int_range(self, data: bytes) -> Tuple[int, int]:
        try:
            value = int.from_bytes(data, byteorder='big')
            return (value, value)
        except:
            return (0, 0)
    
    def _analyze_char_distribution(self, data: bytes) -> Dict:
        try:
            char_counts = {}
            for b in data:
                if chr(b).isprintable():
                    char_counts[chr(b)] = char_counts.get(chr(b), 0) + 1
            return char_counts
        except:
            return {}

    def extract_packet_features(self, pcap_file: str) -> List[Dict]:
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            print(f"Error reading pcap file: {e}")
            return []
            
        features = []
        
        for packet in packets:
            try:
                if 'UDP' in packet and packet['UDP'].dport == 10000:
                    payload = bytes(packet['UDP'].payload)
                    if payload:
                        packet_features = self._analyze_payload(payload)
                        if packet_features:
                            features.append(packet_features)
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue
                
        return features

    def train_model(self, training_pcaps: List[str]):
        all_features = []
        
        for pcap_file in training_pcaps:
            try:
                features = self.extract_packet_features(pcap_file)
                if features:
                    all_features.extend(features)
            except Exception as e:
                print(f"Error processing training file {pcap_file}: {e}")
                continue
        
        if not all_features:
            raise ValueError("No valid features extracted from training data")
        
        # Convert all features to DataFrame ensuring scalar values
        feature_dict = {}
        for feature_set in all_features:
            for key, value in feature_set.items():
                if key not in feature_dict:
                    feature_dict[key] = []
                feature_dict[key].append(self._convert_to_scalar(value))
        
        X = pd.DataFrame(feature_dict)
        X = X.fillna(0)
        
        # Generate labels
        y = np.zeros(len(X))  # Placeholder labels
        
        # Split and train
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
        self.model.fit(X_train, y_train)
        
        return self.model.score(X_test, y_test)

    def analyze_protocol(self, pcap_file: str) -> Dict:
        try:
            features = self.extract_packet_features(pcap_file)
            if not features:
                return {'error': 'No valid features extracted'}
                
            results = {
                'field_analysis': {},
                'dynamic_arrays': [],
                'size_dependent_fields': [],
                'value_ranges': {}
            }
            
            # Process features
            for feature_set in features:
                for field_name in self.protocol_fields['name']:
                    pattern_key = f"{field_name}_repeated_patterns"
                    if pattern_key in feature_set and feature_set[pattern_key] > 0.8:
                        if field_name not in results['dynamic_arrays']:
                            results['dynamic_arrays'].append(field_name)
                    
                    range_min_key = f"{field_name}_range_min"
                    range_max_key = f"{field_name}_range_max"
                    if range_min_key in feature_set and range_max_key in feature_set:
                        results['value_ranges'][field_name] = {
                            'min': feature_set[range_min_key],
                            'max': feature_set[range_max_key]
                        }
            
            return results
            
        except Exception as e:
            print(f"Error in protocol analysis: {e}")
            return {'error': str(e)}

if __name__ == "__main__":
    try:
        db_config = {
            'host': 'localhost',
            'user': 'root',
            'password': 'admin',
            'database': 'project'
        }

        dpi_builder = ProtocolDPIBuilder(db_config)
        dpi_builder.load_protocol_structure()

        training_pcaps = ['/mnt/c/Users/aviv/Desktop/newProject/data/new4.pcapng', '/mnt/c/Users/aviv/Desktop/newProject/data/new4.pcapng']
        accuracy = dpi_builder.train_model(training_pcaps)
        print(f"Model accuracy: {accuracy}")

        results = dpi_builder.analyze_protocol('/mnt/c/Users/aviv/Desktop/newProject/data/new4.pcapng')
        print("Analysis results:\n", json.dumps(results, indent=2))
        
    except Exception as e:
        print(f"Error in main execution: {e}")