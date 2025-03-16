# protocol_def.py
from dataclasses import dataclass
from enum import IntEnum
import struct

class MessageType(IntEnum):
    LOGIN = 1
    DATA_REQUEST = 2
    DATA_RESPONSE = 3
    ERROR = 4
    HEARTBEAT = 5

@dataclass
class ProtocolHeader:
    version: int  # 1 byte
    msg_type: MessageType  # 1 byte
    sequence: int  # 2 bytes
    payload_length: int  # 2 bytes

    @classmethod
    def pack(cls, version, msg_type, sequence, payload_length):
        return struct.pack('!BBHH', version, msg_type, sequence, payload_length)

    @classmethod
    def unpack(cls, data):
        version, msg_type, sequence, payload_length = struct.unpack('!BBHH', data)
        return cls(version, MessageType(msg_type), sequence, payload_length)

@dataclass
class LoginPayload:
    user_id: int  # 4 bytes
    username_length: int  # 1 byte
    username: str  # variable length
    password_length: int  # 1 byte
    password: str  # variable length

    def pack(self):
        return struct.pack(
            f'!IB{len(self.username)}sB{len(self.password)}s',
            self.user_id,
            len(self.username),
            self.username.encode(),
            len(self.password),
            self.password.encode()
        )

@dataclass
class DataRequestPayload:
    request_id: int  # 4 bytes
    data_type: int  # 1 byte
    timestamp: int  # 8 bytes

    def pack(self):
        return struct.pack('!IBQ', self.request_id, self.data_type, self.timestamp)

@dataclass
class DataResponsePayload:
    request_id: int  # 4 bytes
    status: int  # 1 byte
    data_length: int  # 2 bytes
    data: bytes  # variable length

    def pack(self):
        return struct.pack(
            f'!IBH{len(self.data)}s',
            self.request_id,
            self.status,
            len(self.data),
            self.data
        )

# server.py
import socket
import time
# from protocol_def import *

def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 10000))
    print("Server listening on port 10000...")

    sequence = 0
    while True:
        data, addr = server_socket.recvfrom(1024)
        
        # Parse header
        header = ProtocolHeader.unpack(data[:6])
        payload = data[6:]

        # Handle message based on type
        response = None
        if header.msg_type == MessageType.LOGIN:
            response = handle_login(payload)
        elif header.msg_type == MessageType.DATA_REQUEST:
            response = handle_data_request(payload)

        if response:
            # Create response header
            resp_header = ProtocolHeader.pack(1, MessageType.DATA_RESPONSE, sequence, len(response))
            server_socket.sendto(resp_header + response, addr)
            sequence = (sequence + 1) % 65536

def handle_login(payload):
    # Simple login response
    return DataResponsePayload(1, 0, 4, b'OK!').pack()

def handle_data_request(payload):
    # Simple data response
    return DataResponsePayload(1, 0, 8, b'TestData').pack()

# client.py
def run_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sequence = 0

    # Send login message
    login = LoginPayload(1234, 4, "user", 4, "pass")
    login_data = login.pack()
    header = ProtocolHeader.pack(1, MessageType.LOGIN, sequence, len(login_data))
    client_socket.sendto(header + login_data, ('127.0.0.1', 10000))
    sequence = (sequence + 1) % 65536

    # Wait for response
    response, _ = client_socket.recvfrom(1024)
    
    # Send data request
    request = DataRequestPayload(1, 1, int(time.time()))
    request_data = request.pack()
    header = ProtocolHeader.pack(1, MessageType.DATA_REQUEST, sequence, len(request_data))
    client_socket.sendto(header + request_data, ('127.0.0.1', 10000))

    # Wait for response
    response, _ = client_socket.recvfrom(1024)
    client_socket.close()


# record_conversation.py
from scapy.all import wrpcap, IP, UDP
import threading
import time

def record_conversation(output_file):
    # Create a socket to capture the traffic
    capture_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    capture_socket.bind(('0.0.0.0', 10001))
    
    packets = []
    
    def capture_traffic():
        while True:
            data, addr = capture_socket.recvfrom(65535)
            packet = IP(src=addr[0], dst='127.0.0.1')/UDP(sport=addr[1], dport=10000)/data
            packets.append(packet)
    
    # Start capture thread
    capture_thread = threading.Thread(target=capture_traffic)
    capture_thread.daemon = True
    capture_thread.start()
    
    # Run server and client
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    
    # Wait a moment for server to start
    time.sleep(1)
    
    # Run client
    run_client()
    
    # Wait a moment to capture all traffic
    time.sleep(2)
    
    # Save the captured packets
    wrpcap(output_file, packets)

if __name__ == "__main__":
    # Record a conversation
    record_conversation("protocol_conversation.pcap")