from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP

from datetime import datetime
import binascii

def try_parse_payload(payload_bytes):
    try:
        # 1. Try UTF-8 decode (for text-based protocols like HTTP, DNS text)
        text = payload_bytes.decode('utf-8')
        print("[📝 Payload decoded as UTF-8 text:]")
        print(text[:200])  # print first 200 chars
    except UnicodeDecodeError:
        # 2. If binary, print hex dump instead
        print("[🔢 Payload in hex:]")
        print(binascii.hexlify(payload_bytes).decode('utf-8'))

def packet_callback(packet):
    print(f"\n[📦 Packet Captured at {datetime.now().strftime('%H:%M:%S')}]")
    
    if IP in packet:
        ip_layer = packet[IP]
        print(f"From: {ip_layer.src} -> To: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

    if TCP in packet:
        tcp_layer = packet[TCP]
        print(f"TCP Port: {tcp_layer.sport} -> {tcp_layer.dport}")
        if Raw in packet:
            print(f"Payload (Raw): {packet[Raw].load[:100]}")
            try_parse_payload(packet[Raw].load)
    elif UDP in packet:
        udp_layer = packet[UDP]
        print(f"UDP Port: {udp_layer.sport} -> {udp_layer.dport}")
        if Raw in packet:
            print(f"Payload (Raw): {packet[Raw].load[:100]}")
            try_parse_payload(packet[Raw].load)

print("[👂 Listening for packets... Press CTRL+C to stop]")
sniff(filter="ip", prn=packet_callback, store=False)
