# simulate_pcap_protocol2.py

from scapy.all import *
import random
import struct

# הגדרת רשימת 5 endpoints קבועים
ENDPOINTS = [
    "192.168.2.10",
    "192.168.2.20",
    "192.168.2.30",
    "192.168.2.40",
    "192.168.2.50"
]

def create_payload():
    """
    בונה Payload לדוגמה עבור Protocol2 הכולל 10 שדות:
      1. header (int, 2 בתים)
      2. version (int, 1 בית)
      3. msg_type (char[10])
      4. seq (int, 4 בתים)
      5. payload_size (int, 2 בתים)
      6. payload (char[payload_size]) – שדה דינמי בהתאם ל-payload_size
      7. timestamp (float, 4 בתים)
      8. source (char[15])
      9. destination (char[15])
      10. checksum (int, 4 בתים)
    """
    # 1. header – נניח ערך בין 100 ל-999
    header = random.randint(100, 999)
    header_bytes = header.to_bytes(2, byteorder='big')
    
    # 2. version – ערך בין 1 ל-3
    version = random.randint(1, 3)
    version_bytes = version.to_bytes(1, byteorder='big')
    
    # 3. msg_type – מחרוזת באורך עד 10 (נמלא במחרוזת ובתים ריקים אם צריך)
    msg_type = random.choice(["INFO", "WARN", "ERROR", "DEBUG"])
    msg_type_bytes = msg_type.encode('utf-8').ljust(10, b' ')
    
    # 4. seq – מספר רץ, נניח בין 1 ל-10000
    seq = random.randint(1, 10000)
    seq_bytes = seq.to_bytes(4, byteorder='big')
    
    # 5. payload_size – נניח בין 5 ל-20
    payload_size = random.randint(5, 20)
    payload_size_bytes = payload_size.to_bytes(2, byteorder='big')
    
    # 6. payload – מחרוזת באורך payload_size
    payload = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=payload_size))
    payload_bytes = payload.encode('utf-8')
    
    # 7. timestamp – ערך רנדומלי בין 0 ל-10000
    timestamp = random.uniform(0, 10000)
    timestamp_bytes = struct.pack('!f', timestamp)
    
    # 8. source – נשתמש בכתובת המקור (תתעדכן מאוחר יותר)
    # 9. destination – נניח שהשרת הוא תמיד 10.0.0.2
    destination = "10.0.0.2"
    destination_bytes = destination.encode('utf-8').ljust(15, b' ')
    
    # 10. checksum – נניח ערך בין 0 ל-65535
    checksum = random.randint(0, 65535)
    checksum_bytes = checksum.to_bytes(4, byteorder='big')
    
    # חישוב "fixed_length" עבור כל השדות הקבועים (למעט שדה המקור, שיותאם בזמן יצירת הפקטה)
    fixed_length = 2 + 1 + 10 + 4 + 2 + payload_size + 4 + 15 + 15 + 4
    # שדה packet_length: אם נרצה לכלול אותו נוכל לחשב, אך בדוגמה זו לא נכלל
    
    # בניית הפקטה הסופית
    # נבנה את ה-Payload ללא שדות "source" ו-"destination" (שיתווספו ברמת ה-IP)
    payload_total = (header_bytes + version_bytes + msg_type_bytes +
                     seq_bytes + payload_size_bytes + payload_bytes +
                     timestamp_bytes + destination_bytes + checksum_bytes)
    return payload_total

def generate_pcap(file_name, num_packets=100):
    packets = []
    for _ in range(num_packets):
        payload = create_payload()
        # בחר מקור מתוך רשימת ה-Endpoints
        src_ip = random.choice(ENDPOINTS)
        # נניח שהתקשורת היא מ-endpoint (src) לשרת (dst)
        pkt = IP(src=src_ip, dst="10.0.0.2") / UDP(sport=random.randint(1024, 65535), dport=10000) / Raw(load=payload)
        packets.append(pkt)
    wrpcap(file_name, packets)
    print(f"PCAP file '{file_name}' generated with {num_packets} packets from endpoints: {ENDPOINTS}")

if __name__ == '__main__':
    generate_pcap("protocol2_sample.pcap", num_packets=100)
