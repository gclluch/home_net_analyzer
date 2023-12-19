# network_scanner.py

import socket
import nmap
import requests
from scapy.all import ARP, Ether, srp
import http.client
import ssl

extended_common_services = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    # ... more ports and services ...
}

known_router_ouis = {
    "00:40:96": "Cisco Systems",
    "00:09:5B": "Netgear",
    "00:05:5D": "D-Link Systems",
    "14:CC:20": "TP-Link",
    "00:11:50": "Belkin",
    # ... add more as needed ...
}

def get_mac_details(mac_address):
    # Query an online API for MAC address details
    url = f'https://api.macvendors.com/{mac_address}'
    response = requests.get(url)
    if response.status_code != 200:
        return 'Unknown Manufacturer'
    return response.content.decode()

def scan_network(ip_range):
    # ARP scan to detect devices
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def scan_ports(ip_address):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip_address, '1-1024')
        banners = {}
        for port in nm[ip_address]['tcp'].keys() if 'tcp' in nm[ip_address] else []:
            service = extended_common_services.get(port, "Unknown")

            # Use specialized banner grabbing for HTTP/HTTPS
            if service == "HTTP":
                banner = grab_banner_http(ip_address, port)
            elif service == "HTTPS":
                banner = grab_banner_https(ip_address, port)
            else:
                banner = grab_banner(ip_address, port)

            banners[port] = {"service": service, "banner": banner if banner else "No Banner"}
        return banners
    except Exception as e:
        return {"Error": f"Failed to scan ports: {str(e)}"}

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

def detect_os_active(ip_address):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip_address, arguments="-A")  # Using -O for OS detection
        if 'osclass' in nm[ip_address]:
            for osclass in nm[ip_address]['osclass']:
                return osclass.get('osfamily', 'Unknown') + " " + osclass.get('osgen', '')
        return "Unknown OS"
    except Exception as e:
        return f"OS detection failed: {str(e)}"


def detect_os_passive(ip_address):
    try:
        with open('/tmp/p0f.log', 'r') as file:
            for line in file:
                if ip_address in line and "os=" in line:
                    parts = line.split('os=')
                    if len(parts) > 1:
                        os_info = parts[1].split('|')[0]
                        return os_info.strip()
        return "Unknown OS (p0f)"
    except Exception as e:
        return f"p0f OS detection failed: {str(e)}"

def infer_device_type(mac_address, open_ports):
    oui = mac_address.replace(":", "")[:6].upper()
    if oui in known_router_ouis:
        return f"Router ({known_router_ouis[oui]})"

    # Example heuristics based on open ports
    if {80, 443}.issubset(open_ports):
        return "Web Server"
    if 22 in open_ports:
        return "SSH Server"
    if 21 in open_ports:
        return "FTP Server"
    if {137, 138, 139, 445}.issubset(open_ports):
        return "Windows Host"
    if 5353 in open_ports:
        return "Apple Device"

    # Add more heuristics as needed

    return "Unknown Device"

def scan_vulnerabilities(ip_address, open_ports):
    vulnerabilities = {}
    for port in open_ports:
        if port == 22:  # SSH
            vulnerabilities[port] = check_ssh_vulnerability(ip_address)
        elif port == 80 or port == 443:  # HTTP/HTTPS
            vulnerabilities[port] = check_http_vulnerability(ip_address)
        # ... more checks for other ports ...

    return vulnerabilities


def check_ssh_vulnerability(ip_address):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip_address, arguments='-p 22 --script ssh2-enum-algos')
        result = nm[ip_address]['tcp'][22]
        if 'script' in result:
            # Check if the result contains any known vulnerable algorithms or configurations
            if 'diffie-hellman-group1-sha1' in result['script']['ssh2-enum-algos']:
                return "Vulnerable to weak encryption algorithms"
        return "No known SSH vulnerabilities detected"
    except Exception as e:
        return f"Error checking SSH vulnerability: {str(e)}"


def check_http_vulnerability(ip_address, port):
    try:
        url = f"http://{ip_address}:{port}" if port == 80 else f"https://{ip_address}:{port}"
        response = requests.get(url, timeout=10, verify=False)  # 'verify=False' for self-signed certs
        server_header = response.headers.get('Server', '')

        if "Apache/2.2" in server_header:
            return "Potential vulnerability in Apache 2.2"
        elif "nginx/1.16" in server_header:
            return "Potential vulnerability in nginx 1.16"
        # ... additional checks based on server response ...

        return "No known HTTP vulnerabilities detected"
    except requests.ConnectionError:
        return "Connection error (Is the server up?)"
    except requests.Timeout:
        return "Request timed out"
    except requests.RequestException as e:
        return f"HTTP check failed: {str(e)}"

def get_p0f_os_info(ip_address):
    try:
        with open('/tmp/p0f.log', 'r') as file:
            for line in file:
                if ip_address in line:
                    # Extract OS information from the log line
                    # This is a simplified example, actual extraction depends on p0f log format
                    return line.split('os=')[1].split(' ')[0]
        return "Unknown OS (p0f)"
    except Exception as e:
        return f"p0f OS detection failed: {str(e)}"
