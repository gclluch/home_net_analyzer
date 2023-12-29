# traffic_analyzer.py

from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time

device_traffic = defaultdict(lambda: {
    "total_packets": 0, "protocols": defaultdict(int),
    "data_volume": 0, "activity_periods": defaultdict(int)
})

def analyze_traffic(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        device_traffic[ip_src]["total_packets"] += 1
        device_traffic[ip_src]["data_volume"] += len(packet)
        if packet.haslayer(TCP):
            device_traffic[ip_src]["protocols"]["TCP"] += 1
        if packet.haslayer(UDP):
            device_traffic[ip_src]["protocols"]["UDP"] += 1
        # Record activity by hour
        hour = time.localtime().tm_hour
        device_traffic[ip_src]["activity_periods"][hour] += 1

def start_traffic_analysis(duration):
    start_time = time.time()
    while time.time() - start_time < duration:
        sniff(prn=analyze_traffic, store=False, timeout=duration - (time.time() - start_time))

def detect_anomalies(device_traffic, baseline_traffic):
    for ip, traffic in device_traffic.items():
        if traffic['total_packets'] > baseline_traffic[ip]['total_packets'] * 1.5:
            print(f"Unusual traffic volume detected for {ip}")
        # Add more anomaly detection logic based on traffic patterns