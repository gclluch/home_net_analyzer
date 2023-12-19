from scapy.all import sniff, IP
from collections import defaultdict

packet_counts = defaultdict(int)

def count_packets(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        packet_counts[ip_src] += 1

# Capture packets continuously or for a specified count
sniff(prn=count_packets, store=False, count=1000) # Adjust the count as needed

# Analyze packet counts
for ip, count in packet_counts.items():
    print(f"IP: {ip}, Packet Count: {count}")
