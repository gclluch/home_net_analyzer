# port_scanner.py
import socket
import nmap
from home_net_analyzer.constants import EXTENDED_COMMON_SERVICES
from home_net_analyzer.banner_utils import *
import logging

def scan_ports(ip_address):
    nm = nmap.PortScanner()
    port_info = {}
    try:
        # Include the -sV option for service version detection
        nm.scan(
            ip_address,
            '1-15000',
            arguments='-sV'
            )

        if 'tcp' in nm[ip_address]:
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
        else:
            # print("No TCP ports found.")
            return {}

    except Exception as e:
        print(f"Error scanning {ip_address}: {str(e)}")
        return {}


def analyze_ports(ip_address, scan_results):
    banners = {}
    for port, details in scan_results.items():
        # print('DETAILS: ', details)

        service = EXTENDED_COMMON_SERVICES.get(port, "Unknown")

        # Use specialized banner grabbing for HTTP/HTTPS
        if service == "DNS":
            banner_info = grab_banner_dns(ip_address, port)
        elif service == "HTTP":  # also works for UPnP
            banner_info = grab_banner_http(ip_address, port)
        elif service == "HTTPS":
            banner_info = grab_banner_https(ip_address, port)
        elif service == "FTP":
            banner_info = grab_banner_ftp(ip_address, port)
        elif service == "SSH":
            banner_info = grab_banner_ssh(ip_address, port)
        elif service == "SMTP":
            banner_info = grab_banner_smtp(ip_address, port)
        elif service == "MQTT":
            banner_info = probe_mqtt_broker(ip_address, port)
        elif service == "POP3":
            banner_info = grab_banner_pop3(ip_address, port)
        elif service == "IMAP":
            banner_info = grab_banner_imap(ip_address, port)
        elif service == "IPP":  # Internet Printing Protocol for printers
            banner_info = grab_printer_banner(ip_address, port)
        else:
            banner = grab_banner_generic(ip_address, port)
            banner_info = {'response': banner}  # Wrap simple banner in a dictionary

        banners[port] = {
            "service": service,
            "banner": construct_banner(details, banner_info)
        }

    return banners


def grab_banner_generic(ip_address, port):
    try:
        socket.setdefaulttimeout(3)
        s = socket.socket()
        s.connect((ip_address, port))
        banner = s.recv(2048).decode().strip()
        s.close()
        return banner
    except Exception as e:
        logging.error(f"Failed to retrieve banner: {str(e)}")
        # return f"Failed to retrieve banner: {str(e)}"
        return None


def construct_banner(details, banner_info):
    if 'error' in banner_info:
        return banner_info['error']  # Directly return the error message

    product = details.get('product', '')
    version = details.get('version', '')
    extra_info = details.get('extra_info', '').strip()
    response = banner_info.get('response', '')

    detailed_banner_parts = [product, f"(Version: {version})" if version else "", extra_info]
    detailed_banner = " ".join(part for part in detailed_banner_parts if part)

    # Construct a comprehensive banner string
    banner_str = f"{detailed_banner}"
    if response:
        banner_str += f" - Response: {response}"

    # Include additional information from banner_info if available
    for key, value in banner_info.items():
        if key != 'response':
            banner_str += f" | {key}: {value}"

    return banner_str if banner_str.strip() else 'No Banner'


# def construct_banner(details, simple_banner):
#     product = details.get('product', '')
#     version = details.get('version', '')
#     extra_info = details.get('extra_info', '').strip()

#     # Constructing the detailed banner
#     detailed_banner_parts = [product, f"(Version: {version})" if version else "", extra_info]
#     detailed_banner = " ".join(part for part in detailed_banner_parts if part)

#     # Including simple banner if it's informative and detailed banner is not empty
#     if detailed_banner:
#         return f"{detailed_banner} - Response: {simple_banner}" if simple_banner else detailed_banner

#     # Fallback to simple banner or 'No Banner'
#     return simple_banner if simple_banner else 'No Banner'
