# simulate_pcap_protocol5_dynamic.py

from scapy.all import *
import random
import time

# רשימת כתובות IP לדוגמה
ENDPOINTS = ["192.168.5.10", "192.168.5.20", "192.168.5.30", "192.168.5.40", "192.168.5.50"]

def create_payload():
    """
    בונה מטען לפרוטוקול החדש עם השדות הבאים:
      1. מזהה פרוטוקול (4 בתים): קבוע 'PTCL'
      2. גרסה (1 בית): ערך אקראי בין 1 ל-3
      3. סוג הודעה (1 בית): 'D' - Data, 'C' - Command, 'E' - Error
      4. מזהה סשן (4 בתים): מספר אקראי בין 1000 ל-9999
      5. מספר סידורי (4 בתים): מספר אקראי בין 1 ל-10000
      6. חותמת זמן (8 בתים): זמן נוכחי במילישניות (מדי Unix epoch)
      7. אורך מטען (4 בתים): אורך הודעה אקראית בין 5 ל-15 בתים
      8. נתוני הודעה (דינמי): מחרוזת אקראית של תווים אלפאנומריים
    """
    # שדה 1: מזהה פרוטוקול
    proto_id = b'PTCL'
    
    # שדה 2: גרסה
    version = random.randint(1, 3)
    version_bytes = version.to_bytes(1, byteorder='big')
    
    # שדה 3: סוג הודעה
    msg_type = random.choice(['D', 'C', 'E'])
    msg_type_bytes = msg_type.encode('utf-8')[:1]
    
    # שדה 4: מזהה סשן
    session_id = random.randint(1000, 9999)
    session_id_bytes = session_id.to_bytes(4, byteorder='big')
    
    # שדה 5: מספר סידורי
    seq_num = random.randint(1, 10000)
    seq_num_bytes = seq_num.to_bytes(4, byteorder='big')
    
    # שדה 6: חותמת זמן במילישניות (8 בתים)
    timestamp = int(time.time() * 1000)
    timestamp_bytes = timestamp.to_bytes(8, byteorder='big')
    
    # שדה 7: אורך מטען
    payload_length = random.randint(5, 15)
    payload_length_bytes = payload_length.to_bytes(4, byteorder='big')
    print(payload_length_bytes, payload_length)
    
    # שדה 8: נתוני הודעה
    payload_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=payload_length))
    payload_data_bytes = payload_str.encode('utf-8')
    
    # שילוב כל השדות בסדר המוגדר
    payload = (proto_id + version_bytes + msg_type_bytes + session_id_bytes +
               seq_num_bytes + timestamp_bytes + payload_length_bytes + payload_data_bytes)
    print(payload)
    return payload

def generate_pcap(file_name, num_packets=50):
    packets = []
    for _ in range(num_packets):
        payload = create_payload()
        # בוחרים כתובת IP מקור אקראית מתוך הרשימה, ושמים כתובת יעד קבועה (לדוגמה: 10.0.0.200)
        src_ip = random.choice(ENDPOINTS)
        pkt = IP(src=src_ip, dst="10.0.0.200") / UDP(sport=random.randint(1024, 65535), dport=10000) / Raw(load=payload)
        packets.append(pkt)
    wrpcap(file_name, packets)
    print(f"קובץ PCAP '{file_name}' נוצר עם {num_packets} חבילות מכתובות: {ENDPOINTS}")

if __name__ == '__main__':
    generate_pcap("testFeb_26_2.pcap", num_packets=100)
