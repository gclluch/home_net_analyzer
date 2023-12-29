# port_scanner.py
import socket
import nmap
from .constants import EXTENDED_COMMON_SERVICES
import http.client
import ssl

# Only disable on secure, internal networks
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def scan_ports(ip_address):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip_address, '1-1024')
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
        else:
            banner = grab_banner(ip_address, port)

        banners[port] = {"service": service, "banner": banner if banner else "No Banner"}
    return banners


def grab_banner(ip_address, port):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip_address, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner
    except:
        return None


def grab_banner_http(ip_address, port):
    try:
        conn = http.client.HTTPConnection(ip_address, port, timeout=10)
        conn.request("GET", "/")
        response = conn.getresponse()
        return f"{response.status} {response.reason}"
    except Exception as e:
        return f"Failed to retrieve banner: {str(e)}"


def grab_banner_https(ip_address, port):
    try:
        # Create an unverified SSL context
        context = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(ip_address, port, context=context, timeout=10)
        conn.request("GET", "/")
        response = conn.getresponse()
        return f"{response.status} {response.reason}"
    except Exception as e:
        return f"Failed to retrieve HTTPS banner: {str(e)}"