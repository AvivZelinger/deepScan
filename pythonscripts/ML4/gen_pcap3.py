#!/usr/bin/env python3
from scapy.all import *
import random
import time

# List of example IP addresses
ENDPOINTS = ["192.168.5.10", "192.168.5.20", "192.168.5.30", "192.168.5.40", "192.168.5.50"]

def create_payload():
    """
    Constructs a payload for the new protocol with the following fields:
      1. signature (4 bytes): Constant 'NPRT'
      2. version (1 byte): Random value between 1 and 3
      3. flags (1 byte bitfield): Random value between 0 and 7
      4. command (1 byte): 'D' (Data), 'C' (Command), or 'E' (Error)
      5. session_id (4 bytes): Random value between 1000 and 9999
      6. msg_id (4 bytes): Random value between 1 and 10000
      7. timestamp (8 bytes): Current time in milliseconds (Unix epoch)
      8. payload_size (4 bytes): Random value between 5 and 15
      9. message (dynamic): Random alphanumeric string of length payload_size
    """
    # Field 1: signature
    signature = b'NPRT'
    
    # Field 2: version
    version = random.randint(1, 3)
    version_bytes = version.to_bytes(1, byteorder='big')
    
    # Field 3: flags (bitfield) - random value from 0 to 7 (3 bits used)
    flags = random.randint(0, 7)
    flags_bytes = flags.to_bytes(1, byteorder='big')
    
    # Field 4: command type
    command = random.choice(['D', 'C', 'E'])
    command_bytes = command.encode('utf-8')[:1]
    
    # Field 5: session_id
    session_id = random.randint(1000, 9999)
    session_id_bytes = session_id.to_bytes(4, byteorder='big')
    
    # Field 6: msg_id (message identifier)
    msg_id = random.randint(1, 10000)
    msg_id_bytes = msg_id.to_bytes(4, byteorder='big')
    
    # Field 7: timestamp in ms
    timestamp = int(time.time() * 1000)
    timestamp_bytes = timestamp.to_bytes(8, byteorder='big')
    
    # Field 8: payload_size
    payload_size = random.randint(5, 15)
    payload_size_bytes = payload_size.to_bytes(4, byteorder='big')
    
    # Field 9: message data
    message_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=payload_size))
    message_bytes = message_str.encode('utf-8')
    
    # Combine all fields in the defined order
    payload = (signature + version_bytes + flags_bytes + command_bytes +
               session_id_bytes + msg_id_bytes + timestamp_bytes +
               payload_size_bytes + message_bytes)
    return payload

def generate_pcap(file_name, num_packets=50):
    packets = []
    for _ in range(num_packets):
        payload = create_payload()
        # Choose a random source IP from the list; use a fixed destination IP (e.g., 10.0.0.200)
        src_ip = random.choice(ENDPOINTS)
        pkt = IP(src=src_ip, dst="10.0.0.200") / UDP(sport=random.randint(1024, 65535), dport=10000) / Raw(load=payload)
        packets.append(pkt)
    wrpcap(file_name, packets)
    print(f"PCAP file '{file_name}' created with {num_packets} packets from addresses: {ENDPOINTS}")

if __name__ == '__main__':
    generate_pcap("march1BitF.pcap", num_packets=100)
