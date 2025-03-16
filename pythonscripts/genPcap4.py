# simulate_pcap_protocol4_fixed.py

from scapy.all import *
import random
import struct

# נגדיר רשימה קבועה של כתובות IP עבור ה-endpoints (לדוגמה, 5 כתובות)
ENDPOINTS = ["192.168.4.10", "192.168.4.20", "192.168.4.30", "192.168.4.40", "192.168.4.50"]

def create_payload():
    """
    בונה Payload לדוגמה עבור Protocol4 עם 7 שדות:
      1. sync (bool, 1 בית)
      2. id (int, 4 בתים)
      3. type (char, 4 בתים)
      4. length (int, 4 בתים) – מגדיר את אורך ה-payload
      5. payload (char, גודל דינמי, מוגדר כ-0 בטבלה)
      6. crc (int, 4 בתים)
      7. flag (bool, 1 בית)
    """
    # 1. sync: נבחר True או False
    sync = random.choice([True, False])
    sync_byte = b'\x01' if sync else b'\x00'
    
    # 2. id: מספר בין 1000 ל-9999
    identifier = random.randint(1000, 9999)
    id_bytes = identifier.to_bytes(4, byteorder='big')
    
    # 3. type: נבחר סוג הודעה מתוך רשימה, ממלא עד 4 בתים
    msg_type = random.choice(["CMD1", "CMD2", "DATA", "ACK "])
    type_bytes = msg_type.encode('utf-8').ljust(4, b' ')
    
    # 4. length: אורך ה-payload – נבחר בין 5 ל-15
    payload_length = random.randint(5, 15)
    length_bytes = payload_length.to_bytes(4, byteorder='big')
    
    # 5. payload: מחרוזת באורך payload_length
    payload_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=payload_length))
    payload_bytes = payload_str.encode('utf-8')
    
    # 6. crc: נניח ערך בין 0 ל-2**32-1
    crc = random.randint(0, 2**32 - 1)
    crc_bytes = crc.to_bytes(4, byteorder='big')
    
    # 7. flag: בוליאני, True או False
    flag = random.choice([True, False])
    flag_byte = b'\x01' if flag else b'\x00'
    
    # בניית הפלט הכולל
    payload_total = (sync_byte + id_bytes + type_bytes +
                     length_bytes + payload_bytes +
                     crc_bytes + flag_byte)
    return payload_total

def generate_pcap(file_name, num_packets=50):
    packets = []
    for _ in range(num_packets):
        payload = create_payload()
        # בחר מקור מתוך רשימת ה-Endpoints, יעד קבוע (לדוגמה, 10.0.0.200)
        src_ip = random.choice(ENDPOINTS)
        pkt = IP(src=src_ip, dst="10.0.0.200") / UDP(sport=random.randint(1024, 65535), dport=10000) / Raw(load=payload)
        packets.append(pkt)
    wrpcap(file_name, packets)
    print(f"PCAP file '{file_name}' generated with {num_packets} packets from endpoints: {ENDPOINTS}")

if __name__ == '__main__':
    generate_pcap("protocol4_sample_fixed.pcap", num_packets=50)
