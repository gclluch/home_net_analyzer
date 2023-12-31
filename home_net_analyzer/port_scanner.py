# port_scanner.py
import socket
import nmap
from .constants import EXTENDED_COMMON_SERVICES
from .banner_utils import *


def scan_ports(ip_address):
    nm = nmap.PortScanner()
    try:

        nm.scan(
            ip_address,
            '1-10000',  # 1-1024, 1-65535
            # arguments='-sV'  # -sV for service version detection
        )
        return [port for port in nm[ip_address].get('tcp', [])]
    except Exception as e:
        return {"Error": f"Failed to scan ports: {str(e)}"}


def scan_ports(ip_address):
    nm = nmap.PortScanner()
    try:
        # Include the -sV option for service version detection
        nm.scan(ip_address, '1-10000', arguments='-sV')

        port_info = {}
        for port in nm[ip_address]['tcp']:
            service_info = nm[ip_address]['tcp'][port]
            service = service_info['name']
            version = service_info['version']
            product = service_info['product']
            extra_info = service_info['extrainfo']

            banner = f"{service}, {product} {version} {extra_info}".strip()
            port_info[port] = {"service": service, "banner": banner}

        return port_info
    except Exception as e:
        return {"Error": f"Failed to scan ports: {str(e)}"}


def analyze_ports(ip_address, open_ports):
    banners = {}
    for port in open_ports:
        service = EXTENDED_COMMON_SERVICES.get(port, "Unknown")

        # Use specialized banner grabbing for HTTP/HTTPS
        if service == "HTTP":  # also works for UPnP
            banner = grab_banner_http(ip_address, port)
        elif service == "HTTPS":
            banner = grab_banner_https(ip_address, port)
        elif service == "FTP":
            banner = grab_banner_ftp(ip_address, port)
        elif service == "SSH":
            banner = grab_banner_ssh(ip_address, port)
        elif service == "SMTP":
            banner = grab_banner_smtp(ip_address, port)
        elif service == "MQTT":
            banner = probe_mqtt_broker(ip_address, port)
        elif service == "IPP":  # Internet Printing Protocol for printers
            banner = grab_printer_banner(ip_address, port)
        else:
            banner = grab_banner(ip_address, port)
        banners[port] = {"service": service, "banner": banner if banner else "No Banner"}
    return banners

def grab_banner(ip_address, port):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip_address, port))
        banner = s.recv(2048).decode().strip()
        s.close()
        return banner
    except:
        return None
