"""
This is an alternative to wireshark that allow us to perform real time analysis
"""
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from collections import defaultdict
import time

# Settings
MONITOR_DURATION = 60  # seconds
THRESHOLD_PORT_SCAN = 10
THRESHOLD_PACKET_RATE = 100

# Tracking
ip_port_access = defaultdict(set)
ip_packet_count = defaultdict(int)
start_time = time.time()

# Suspicious ports
suspicious_ports = {21: 'FTP', 23: 'Telnet', 3389: 'RDP', 5900: 'VNC'}

def analyze_packet(pkt):
    global start_time
    now = time.time()

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_port = None

        if TCP in pkt or UDP in pkt:
            l4 = pkt[TCP] if TCP in pkt else pkt[UDP]
            dst_port = l4.dport
            ip_port_access[src_ip].add(dst_port)
            ip_packet_count[src_ip] += 1

            if len(ip_port_access[src_ip]) > THRESHOLD_PORT_SCAN:
                print(f"[⚠️  ALERT] Port Scan from {src_ip}: Ports -> {ip_port_access[src_ip]}")

            if dst_port in suspicious_ports:
                print(f"[⚠️  ALERT] Suspicious Port Access: {src_ip} -> {suspicious_ports[dst_port]} ({dst_port})")

        if now - start_time > MONITOR_DURATION:
            print("\n📊 Packet Rate Summary:")
            for ip, count in ip_packet_count.items():
                print(f"  {ip}: {count} packets/min")
                if count > THRESHOLD_PACKET_RATE:
                    print(f"  [🚨 TRAFFIC ALERT] High traffic from {ip} ({count} p/min)")

            # Reset
            start_time = now
            ip_port_access.clear()
            ip_packet_count.clear()

def start_monitor(interface=None):
    print("🔍 Monitoring... (Ctrl+C to stop)")
    sniff(prn=analyze_packet, store=0)



if __name__ == "__main__":
    start_monitor("wlan")