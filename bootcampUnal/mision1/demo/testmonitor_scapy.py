
from scapy.all import send
from scapy.layers.inet import IP, TCP

import time

TARGET_IP = "127.0.0.1"  # Change to your IP under test

def simulate_port_scan():
    print("🚨 Simulating Port Scan...")
    for port in range(20, 40):
        pkt = IP(dst=TARGET_IP)/TCP(dport=port)
        send(pkt, verbose=0)
        time.sleep(0.1)

def simulate_high_traffic():
    print("📈 Simulating High Packet Rate...")
    for _ in range(120):
        pkt = IP(dst=TARGET_IP)/TCP(dport=80)
        send(pkt, verbose=0)
        time.sleep(0.3)  # Slow enough to show rate changes

def simulate_suspicious_service_access():
    print("🔒 Simulating Suspicious Port Access (FTP, Telnet)...")
    for port in [21, 23, 3389]:
        pkt = IP(dst=TARGET_IP)/TCP(dport=port)
        send(pkt, verbose=0)
        time.sleep(0.5)

if __name__ == "__main__":
    simulate_port_scan()
    simulate_suspicious_service_access()
    simulate_high_traffic()
