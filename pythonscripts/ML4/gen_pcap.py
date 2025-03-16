# simulate_pcap_protocol4_dynamic.py

from scapy.all import *
import random
import struct

# Define a fixed list of endpoint IP addresses
ENDPOINTS = ["192.168.4.10", "192.168.4.20", "192.168.4.30", "192.168.4.40", "192.168.4.50"]

def create_payload():
    """
    Constructs a payload for the protocol with 6 fields:
      1. checksum (int, 4 bytes)
      2. end_flag (char, 1 byte)
      3. flag (char, 1 byte)
      4. id (int, 4 bytes)
      5. length (int, 4 bytes) – defines the length of the message field
      6. message (char, dynamic; its size is defined by the 'length' field)
    """
    # Field 1: checksum (4 bytes int)
    checksum = random.randint(0, 2**32 - 1)
    checksum_bytes = checksum.to_bytes(4, byteorder='big')
    
    # Field 2: end_flag (1 byte char) – choose 'Y' or 'N'
    end_flag = random.choice(['Y', 'N'])
    end_flag_bytes = end_flag.encode('utf-8')[:1]
    
    # Field 3: flag (1 byte char) – choose 'Y' or 'N'
    flag = random.choice(['Y', 'N'])
    flag_bytes = flag.encode('utf-8')[:1]
    
    # Field 4: id (4 bytes int) – a random identifier between 1000 and 9999
    identifier = random.randint(1000, 9999)
    id_bytes = identifier.to_bytes(4, byteorder='big')
    
    # Field 5: length (4 bytes int) – defines the length of the message; choose a value between 5 and 15
    msg_length = random.randint(5, 15)
    length_bytes = msg_length.to_bytes(4, byteorder='big')
    
    # Field 6: message (dynamic char field, size defined by the 'length' field)
    message_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=msg_length))
    message_bytes = message_str.encode('utf-8')
    
    # Combine all fields in the defined order
    payload = checksum_bytes + end_flag_bytes + flag_bytes + id_bytes + length_bytes + message_bytes
    return payload

def generate_pcap(file_name, num_packets=50):
    packets = []
    for _ in range(num_packets):
        payload = create_payload()
        # Choose a source IP from the endpoints; use a fixed destination (e.g., 10.0.0.200)
        src_ip = random.choice(ENDPOINTS)
        pkt = IP(src=src_ip, dst="10.0.0.200") / UDP(sport=random.randint(1024, 65535), dport=10000) / Raw(load=payload)
        packets.append(pkt)
    wrpcap(file_name, packets)
    print(f"PCAP file '{file_name}' generated with {num_packets} packets from endpoints: {ENDPOINTS}")

if __name__ == '__main__':
    generate_pcap("test.pcap", num_packets=100)
