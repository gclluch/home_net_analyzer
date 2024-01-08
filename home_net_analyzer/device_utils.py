"""
Device Utilities Module

This module contains utility functions for device analysis in a network environment.
It includes methods for retrieving manufacturer details based on MAC addresses and
inferring device types based on open ports and other network characteristics.

Functions:
    get_mac_details(mac_address): Retrieves the manufacturer details based on the MAC address.
    infer_device_type(mac_address, open_ports): Infers the device type based on MAC address and open ports.

The module utilizes external services for MAC address lookup and implements heuristic
methods for device type inference.

"""

import requests
from home_net_analyzer.constants import KNOWN_ROUTER_OUIS

##### Device Detail Utils #####


def get_mac_details(mac_address):
    """
    Retrieves the manufacturer details for a given MAC address via external API

    Args:
        mac_address (str): The MAC address to query.

    Returns:
        str: The manufacturer name associated with the MAC address. Returns
             'Unknown Manufacturer' if the API call is unsuccessful or if the
             MAC address is not recognized.
    """
    url = f'https://api.macvendors.com/{mac_address}'
    response = requests.get(url)
    if response.status_code != 200:
        return 'Unknown Manufacturer'
    return response.content.decode()


def infer_device_type(mac_address, open_ports):
    """
    Infers the type of device based on its MAC address and open ports.

    This function uses the MAC address's OUI (Organizationally Unique Identifier)
    and the set of open ports to determine the most likely type of device.

    Args:
        mac_address (str): The MAC address of the device.
        open_ports (list): A set of integers representing the open ports on the device.

    Returns:
        str: The inferred device type based on the MAC address and open ports.
             Returns 'Unknown Device' if the device type cannot be determined.
    """
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
