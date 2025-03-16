# simulate_pcap_protocol3.py

from scapy.all import IP, UDP, Raw, wrpcap
import random
import struct

# הגדרת 5 כתובות IP של endpoints
ENDPOINTS = ["192.168.3.10", "192.168.3.20", "192.168.3.30", "192.168.3.40", "192.168.3.50"]

def create_payload():
    """
    בונה Payload עבור Protocol3 עם 6 שדות:
      1. start_flag (bool, 1 בית)
      2. msg_id (int, 4 בתים)
      3. command (char[8])
      4. data_length (int, 2 בתים)
      5. data (char[data_length]) – שדה דינמי (אם data_length הוא 0, נתפס את שאר הpayload)
      6. end_flag (bool, 1 בית)
    """
    # 1. start_flag – נבחר True או False
    start_flag = random.choice([True, False])
    start_flag_byte = b'\x01' if start_flag else b'\x00'
    
    # 2. msg_id – נניח מספר בין 1000 ל-9999
    msg_id = random.randint(1000, 9999)
    msg_id_bytes = msg_id.to_bytes(4, byteorder='big')
    
    # 3. command – נבחר פקודה מתוך רשימה; יש למלא עד 8 בתים
    command = random.choice(["START", "STOP", "DATA", "RESET"])
    command_bytes = command.encode('utf-8').ljust(8, b' ')
    
    # 4. data_length – נבחר באופן אקראי בין 0 ל-20
    # אם data_length=0, נתפס את השאר של ה-payload כערך
    data_length = random.randint(0, 20)
    data_length_bytes = data_length.to_bytes(2, byteorder='big')
    
    # 5. data – אם data_length > 0, בונה מחרוזת באורך זה, אחרת נשלח מחרוזת ריקה
    if data_length > 0:
        data_field = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=data_length))
    else:
        data_field = ''
    data_bytes = data_field.encode('utf-8')
    
    # 6. end_flag – נבחר True או False
    end_flag = random.choice([True, False])
    end_flag_byte = b'\x01' if end_flag else b'\x00'
    
    # בניית Payload – אם data_length==0, נניח שהשדה הדינמי תופס את כל מה שנשאר (כאן זה נראה כאילו אין נתונים נוספים)
    # במקרה זה, אנו פשוט משתמשים בערך data_bytes כפי שהוא (ריק)
    payload = (start_flag_byte + msg_id_bytes + command_bytes +
               data_length_bytes + data_bytes + end_flag_byte)
    return payload

def generate_pcap(file_name, num_packets=50):
    packets = []
    for _ in range(num_packets):
        payload = create_payload()
        # בחר באופן אקראי כתובת IP מקור מתוך ENDPOINTS, יעד קבוע 10.0.0.100
        src_ip = random.choice(ENDPOINTS)
        pkt = IP(src=src_ip, dst="10.0.0.100") / UDP(sport=random.randint(1024, 65535), dport=10000) / Raw(load=payload)
        packets.append(pkt)
    wrpcap(file_name, packets)
    print(f"PCAP file '{file_name}' generated with {num_packets} packets from endpoints: {ENDPOINTS}")

if __name__ == '__main__':
    generate_pcap("protocol3_sample3.pcap", num_packets=500)
    generate_pcap("protocol3_sample4.pcap", num_packets=500)
    generate_pcap("protocol3_sample5.pcap", num_packets=500)
    generate_pcap("protocol3_sample6.pcap", num_packets=500)
    generate_pcap("protocol3_sample7.pcap", num_packets=500)    
    
