# simulate_pcap_test.py

from scapy.all import *
import random
import struct
from scapy.layers.inet import IP, UDP

def create_payload():
    """
    בונה Payload לדוגמה לפי המבנה:
      1. version (int, 2 בתים)
      2. packet_length (int, 4 בתים)
      3. timestamp (float, 4 בתים)
      4. source_ip (char[15])
      5. destination_ip (char[15])
      6. message_id (int, 4 בתים)
      7. status_code (int, 2 בתים)
      8. payload_length (int, 2 בתים)
      9. payload (char[payload_length]) – דינמי
      10. checksum (int, 4 בתים)
      11. flags (bool, 1 בית)
      12. priority (int, 1 בית)
      13. session_id (int, 4 בתים)
      14. error_code (int, 2 בתים)
      15. retries (int, 1 בית)
    """
    # שדה version – נניח ערך בין 1 ל-5
    version = random.randint(1, 5)
    version_bytes = version.to_bytes(2, byteorder='big')
    
    # שדה packet_length – נחשב את האורך הכולל של הפקטה
    # נחשב את האורך של השדות הקבועים
    fixed_length = 2 + 4 + 4 + 15 + 15 + 4 + 2 + 2 + 4 + 1 + 1 + 4 + 2 + 1
    # שדה payload_length – נניח בין 5 ל-20
    payload_length = random.randint(5, 20)
    payload_length_bytes = payload_length.to_bytes(2, byteorder='big')
    
    # שדה packet_length כולל את כל השדות
    packet_length = fixed_length + payload_length
    packet_length_bytes = packet_length.to_bytes(4, byteorder='big')
    
    # שדה timestamp – נניח ערך רנדומלי בין 0 ל-10000
    timestamp = random.uniform(0, 10000)
    timestamp_bytes = struct.pack('!f', timestamp)
    
    # שדות source_ip ו-destination_ip – מחרוזות באורך 15 בתים
    source_ip = "172.16.0." + str(random.randint(2, 254))
    source_ip_bytes = source_ip.encode('utf-8').ljust(15, b' ')
    
    destination_ip = "10.0.0.1"  # נניח שהשרת הוא תמיד זה
    destination_ip_bytes = destination_ip.encode('utf-8').ljust(15, b' ')
    
    # שדה message_id – נניח ערך בין 1000 ל-9999
    message_id = random.randint(1000, 9999)
    message_id_bytes = message_id.to_bytes(4, byteorder='big')
    
    # שדה status_code – נניח ערך בין 0 ל-99
    status_code = random.randint(0, 99)
    status_code_bytes = status_code.to_bytes(2, byteorder='big')
    
    # שדה payload – מחרוזת באורך payload_length
    payload = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=payload_length))
    payload_bytes = payload.encode('utf-8')
    
    # שדה checksum – נניח ערך בין 0 ל-65535
    checksum = random.randint(0, 65535)
    checksum_bytes = checksum.to_bytes(4, byteorder='big')
    
    # שדה flags – True או False
    flags = random.choice([True, False])
    flags_byte = b'\x01' if flags else b'\x00'
    
    # שדה priority – נניח ערך בין 1 ל-5
    priority = random.randint(1, 5)
    priority_byte = priority.to_bytes(1, byteorder='big')
    
    # שדה session_id – נניח ערך בין 10000 ל-99999
    session_id = random.randint(10000, 99999)
    session_id_bytes = session_id.to_bytes(4, byteorder='big')
    
    # שדה error_code – נניח ערך בין 0 ל-99
    error_code = random.randint(0, 99)
    error_code_bytes = error_code.to_bytes(2, byteorder='big')
    
    # שדה retries – נניח ערך בין 0 ל-5
    retries = random.randint(0, 5)
    retries_byte = retries.to_bytes(1, byteorder='big')
    
    # בניית הפקטה
    payload_field = payload_bytes.ljust(payload_length, b' ')  # מילוי ברווחים במידת הצורך
    
    payload_total = (
        version_bytes + packet_length_bytes + timestamp_bytes +
        source_ip_bytes + destination_ip_bytes + message_id_bytes +
        status_code_bytes + payload_length_bytes + payload_field +
        checksum_bytes + flags_byte + priority_byte +
        session_id_bytes + error_code_bytes + retries_byte
    )
    
    return payload_total

def generate_pcap(file_name, num_packets=50):
    packets = []
    for _ in range(num_packets):
        payload = create_payload()
        # בחר צד: נשלח מ־endpoint לשרת (פורט 10000) או מהשרת ל-endpoint
        if random.choice([True, False]):
            # Endpoint to Server
            src_ip = "172.16.0." + str(random.randint(2, 254))
            pkt = IP(src=src_ip, dst="10.0.0.1") / UDP(sport=random.randint(1024,65535), dport=10000) / Raw(load=payload)
        else:
            # Server to Endpoint
            dst_ip = "172.16.0." + str(random.randint(2, 254))
            pkt = IP(src="10.0.0.1", dst=dst_ip) / UDP(sport=10000, dport=random.randint(1024,65535)) / Raw(load=payload)
        packets.append(pkt)
    # שמור את הפקטות לקובץ PCAP
    wrpcap(file_name, packets)
    print(f"Test PCAP file '{file_name}' generated with {num_packets} packets.")

if __name__ == '__main__':
    generate_pcap("test_sample.pcap", num_packets=50)
