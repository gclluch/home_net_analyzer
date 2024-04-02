# scanner.py
from .port_scanner import scan_ports, analyze_ports
from .os_detector import detect_os_active, detect_os_passive
from .vulnerability import scan_vulnerabilities
from .device_utils import get_mac_details, infer_device_type
from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    # ARP scan to detect devices
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices
