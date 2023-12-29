# network_scanner.py

import socket
import nmap
import requests
from scapy.all import ARP, Ether, srp
import http.client
import ssl
import ftplib
import smtplib

from constants import EXTENDED_COMMON_SERVICES, KNOWN_ROUTER_OUIS


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


def analyze_ports(ip_address, open_ports):
    banners = {}
    for port in open_ports:
        service = EXTENDED_COMMON_SERVICES.get(port, "Unknown")

        # Use specialized banner grabbing
        if service in ["HTTP", "HTTPS"]:
            banner = grab_banner_http_https(ip_address, port, service)
        else:
            banner = grab_banner(ip_address, port)

        banners[port] = {"service": service, "banner": banner if banner else "No Banner"}
    return banners


def scan_ports(ip_address):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip_address, '1-1024')
        open_ports = [port for port in nm[ip_address]['tcp'].keys() if 'tcp' in nm[ip_address]]
        return open_ports
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


def grab_banner_http_https(ip_address, port, service):
    try:
        url = f"http://{ip_address}:{port}" if service == "HTTP" else f"https://{ip_address}:{port}"
        context = None if service == "HTTP" else ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(ip_address, port, context=context, timeout=10) if service == "HTTPS" \
            else http.client.HTTPConnection(ip_address, port, timeout=10)
        conn.request("GET", "/")
        response = conn.getresponse()
        return f"{response.status} {response.reason}"
    except Exception as e:
        return f"Failed to retrieve banner: {str(e)}"


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
    if oui in KNOWN_ROUTER_OUIS:
        return f"Router ({KNOWN_ROUTER_OUIS[oui]})"

    # Enhanced heuristics based on open ports
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

    # Additional logic for IoT and smart devices
    if {1883, 8883}.issubset(open_ports):
        return "MQTT Device (IoT)"
    if 5683 in open_ports:
        return "CoAP Device (IoT)"

    # Device type based on combination of ports
    if {80, 443, 22}.issubset(open_ports):
        return "Multi-Service Device"

    return "Unknown Device"

def scan_vulnerabilities(ip_address, open_ports):
    vulnerabilities = {}
    for port in open_ports:
        if port == 22:  # SSH
            vulnerabilities[port] = check_ssh_vulnerability(ip_address)
        elif port in [80, 443]:  # HTTP/HTTPS
            vulnerabilities[port] = check_http_vulnerability(ip_address, port)
        elif port == 21:  # FTP
            vulnerabilities[port] = check_ftp_vulnerability(ip_address)
        elif port == 25 or port == 587:  # SMTP
            vulnerabilities[port] = check_smtp_vulnerability(ip_address)
        # ... more checks for other ports ...

    return vulnerabilities


def check_ssh_vulnerability(ip_address):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip_address, arguments='-p 22 --script ssh-hostkey,ssh2-enum-algos')
        result = nm[ip_address]['tcp'][22]
        vulnerabilities = []

        # Check for weak algorithms
        if 'ssh2-enum-algos' in result['script']:
            if 'diffie-hellman-group1-sha1' in result['script']['ssh2-enum-algos']:
                vulnerabilities.append("Weak encryption algorithm (diffie-hellman-group1-sha1)")

        # Check for known vulnerable host keys
        if 'ssh-hostkey' in result['script']:
            keys = result['script']['ssh-hostkey']
            for key_type, key_data in keys.items():
                if key_type in ['rsa', 'dsa', 'ecdsa']:
                    key_length = int(key_data.split()[0])
                    if key_type == 'rsa' and key_length < 2048:
                        vulnerabilities.append(f"RSA key too short: {key_length} bits")
                    elif key_type == 'dsa' and key_length != 1024:
                        vulnerabilities.append("DSA key length not 1024 bits")
                    # Add more logic for other key types and known issues

        return vulnerabilities if vulnerabilities else "No known SSH vulnerabilities detected"
    except Exception as e:
        return f"Error checking SSH vulnerability: {str(e)}"


def check_http_vulnerability(ip_address, port):
    try:
        url = f"http://{ip_address}:{port}" if port == 80 else f"https://{ip_address}:{port}"
        response = requests.get(url, timeout=10, verify=False)
        server_header = response.headers.get('Server', '')
        vulnerabilities = []

        # Check for known vulnerabilities based on server header
        if "Apache/2.2" in server_header:
            vulnerabilities.append("Potential vulnerability in Apache 2.2")
        elif "nginx/1.16" in server_header:
            vulnerabilities.append("Potential vulnerability in nginx 1.16")
        # ... additional checks based on server response ...

        return vulnerabilities if vulnerabilities else "No known HTTP vulnerabilities detected"
    except requests.ConnectionError:
        return ["Connection error (Is the server up?)"]
    except requests.Timeout:
        return ["Request timed out"]
    except requests.RequestException as e:
        return [f"HTTP check failed: {str(e)}"]


def check_ftp_vulnerability(ip_address):
    vulnerabilities = []
    try:
        ftp = ftplib.FTP(ip_address)
        ftp.login()  # Attempting anonymous login
        vulnerabilities.append("Anonymous FTP login is allowed")
    except ftplib.error_perm:
        # Handle error if anonymous login is not allowed
        pass
    except Exception as e:
        return [f"Error checking FTP vulnerability: {str(e)}"]

    # Add more checks here (e.g., checking server banner for known vulnerable versions)

    return vulnerabilities if vulnerabilities else ["No known FTP vulnerabilities detected"]


def check_smtp_vulnerability(ip_address):
    vulnerabilities = []
    try:
        with smtplib.SMTP(ip_address) as smtp:
            banner = smtp.docmd("NOOP")
            if "220" in banner:
                vulnerabilities.append("SMTP server accessible")

            # Check for open relay
            status, _ = smtp.docmd("MAIL FROM:<test@example.com>")
            if "250" in status:
                status, _ = smtp.docmd("RCPT TO:<test@example.com>")
                if "250" in status:
                    vulnerabilities.append("Potential open relay detected")

            # Add more checks here for specific SMTP vulnerabilities
    except Exception as e:
        return [f"Error checking SMTP vulnerability: {str(e)}"]

    return vulnerabilities if vulnerabilities else ["No known SMTP vulnerabilities detected"]

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
