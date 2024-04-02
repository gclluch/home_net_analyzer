# port_scanner.py
import socket
import nmap
from home_net_analyzer.constants import EXTENDED_COMMON_SERVICES
from home_net_analyzer.banner_utils import *


def scan_ports(ip_address):
    nm = nmap.PortScanner()
    try:
        # Include the -sV option for service version detection
        nm.scan(
            ip_address,
            '1-1024',
            arguments='-sV'
            )

        port_info = {}
        for port in nm[ip_address]['tcp']:
            service_info = nm[ip_address]['tcp'][port]
            service = service_info['name']
            version = service_info['version']
            product = service_info['product']
            extra_info = service_info['extrainfo']

            port_info[port] = {
                "service": service,
                "product": product,
                "version": version,
                "extra_info": extra_info
                }

        return port_info
    except Exception as e:
        return {"Error": f"Failed to scan ports: {str(e)}"}


def analyze_ports(ip_address, scan_results):
    banners = {}
    for port, details in scan_results.items():
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

        banners[port] = {
            "service": service,
            "banner": construct_banner(details, banner)
            }

    return banners


def grab_banner(ip_address, port):
    try:
        socket.setdefaulttimeout(3)
        s = socket.socket()
        s.connect((ip_address, port))
        banner = s.recv(2048).decode().strip()
        s.close()
        return banner
    except:
        return None


def construct_banner(details, simple_banner):
    product = details.get('product', '')
    version = details.get('version', '')
    extra_info = details.get('extra_info', '').strip()

    # Constructing the detailed banner
    detailed_banner_parts = [product, f"(Version: {version})" if version else "", extra_info]
    detailed_banner = " ".join(part for part in detailed_banner_parts if part)

    # Including simple banner if it's informative and detailed banner is not empty
    if detailed_banner:
        return f"{detailed_banner} - Response: {simple_banner}" if simple_banner else detailed_banner

    # Fallback to simple banner or 'No Banner'
    return simple_banner if simple_banner else 'No Banner'
