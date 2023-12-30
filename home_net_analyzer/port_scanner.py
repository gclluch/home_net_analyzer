# port_scanner.py
import nmap
from .constants import EXTENDED_COMMON_SERVICES
from .banner_utils import *


def scan_ports(ip_address):
    nm = nmap.PortScanner()
    try:

        nm.scan(
            ip_address,
            '1-2048',  # 1-1024, 1-65535
            # arguments='-sV'  # -sV for service version detection
        )
        return [port for port in nm[ip_address].get('tcp', [])]
    except Exception as e:
        return {"Error": f"Failed to scan ports: {str(e)}"}


def analyze_ports(ip_address, open_ports):
    banners = {}
    for port in open_ports:
        service = EXTENDED_COMMON_SERVICES.get(port, "Unknown")

        # Use specialized banner grabbing for HTTP/HTTPS
        if service == "HTTP":
            banner = grab_banner_http(ip_address, port)
        elif service == "HTTPS":
            banner = grab_banner_https(ip_address, port)
        elif service == "FTP":
            banner = grab_banner_ftp(ip_address, port)
        elif service == "SSH":
            banner = grab_banner_ssh(ip_address, port)
        elif service == "SMTP":
            banner = grab_banner_smtp(ip_address, port)
        # Add more services here...
        else:
            banner = grab_banner(ip_address, port)
        banners[port] = {"service": service, "banner": banner if banner else "No Banner"}
    return banners
