# utils.py
import requests
import nmap
import ftplib
import smtplib
import dns.resolver
import dns.exception
from smb.SMBConnection import SMBConnection
import logging
from home_net_analyzer.constants import KNOWN_ROUTER_OUIS

##### Device Detail Utils #####


def get_mac_details(mac_address):
    # Query an online API for MAC address details
    url = f'https://api.macvendors.com/{mac_address}'
    response = requests.get(url)
    if response.status_code != 200:
        return 'Unknown Manufacturer'
    return response.content.decode()


def infer_device_type(mac_address, open_ports):
    oui = mac_address.replace(":", "")[:6].upper()
    if oui in KNOWN_ROUTER_OUIS:
        return f"Router ({KNOWN_ROUTER_OUIS[oui]})"

    # Enhanced heuristics based on open ports
    if {80, 443}.issubset(open_ports):
        if 22 in open_ports:
            return "Managed Web Server"
        return "Web Server"
    if {21, 22, 80, 443}.issubset(open_ports):
        return "Web Hosting Server"
    if 22 in open_ports:
        return "SSH Server"
    if 21 in open_ports:
        return "FTP Server"
    if {137, 138, 139, 445}.issubset(open_ports):
        return "Windows Host"
    if 5353 in open_ports:
        return "Apple Device"
    if 23 in open_ports:
        return "Telnet Service"
    if 3306 in open_ports:
        return "MySQL Server"
    if 5060 in open_ports or 5061 in open_ports:
        return "VoIP Server"
    if 5900 in open_ports:
        return "VNC Server"
    if 25 in open_ports or 587 in open_ports:
        return "Mail Server"
    if 161 in open_ports or 162 in open_ports:
        return "SNMP Device"
    if 3389 in open_ports:
        return "Remote Desktop Service"
    if {1883, 8883}.issubset(open_ports):
        return "MQTT Device (IoT)"
    if 5683 in open_ports:
        return "CoAP Device (IoT)"
    if 9100 in open_ports:
        return "Network Printer"
    if 3478 in open_ports or 5349 in open_ports:
        return "STUN/TURN Service"
    if 1935 in open_ports or 5080 in open_ports:
        return "Streaming Server"
    if any(port in range(6881, 6890) for port in open_ports):
        return "Torrent Server"
    if 53 in open_ports:
        return "DNS Server"
    if {67, 68}.issubset(open_ports):
        return "DHCP Server"
    if 554 in open_ports or 8554 in open_ports:
        return "Surveillance Camera"
    # Device type based on combination of ports
    if {80, 443, 22}.issubset(open_ports):
        return "Multi-Service Device"

    return "Unknown Device"
