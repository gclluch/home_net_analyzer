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


##### Vulnerability Scan Utils #####


def check_ssh_vulnerability(ip_address):
    nm = nmap.PortScanner()
    try:
        nm.scan(
            ip_address,
            arguments='-p 22 --script ssh-hostkey,ssh2-enum-algos')
        result = nm[ip_address]['tcp'][22]
        vulnerabilities = []

        # Check for weak algorithms
        if 'ssh2-enum-algos' in result['script']:
            if 'diffie-hellman-group1-sha1' in result['script']['ssh2-enum-algos']:
                vulnerabilities.append(
                    "Weak encryption algorithm (diffie-hellman-group1-sha1)")

        # Check for known vulnerable host keys
        if 'ssh-hostkey' in result['script']:
            keys = result['script']['ssh-hostkey']
            for key_type, key_data in keys.items():
                if key_type in ['rsa', 'dsa', 'ecdsa']:
                    key_length = int(key_data.split()[0])
                    if key_type == 'rsa' and key_length < 2048:
                        vulnerabilities.append(
                            f"RSA key too short: {key_length} bits")
                    elif key_type == 'dsa' and key_length != 1024:
                        vulnerabilities.append("DSA key length not 1024 bits")
                    # Add more logic for other key types and known issues

        return vulnerabilities if vulnerabilities else [
            "No known SSH vulnerabilities detected"]
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

        # Check for insecure HTTP methods (e.g., TRACE, PUT)
        if 'Allow' in response.headers:
            if 'TRACE' in response.headers['Allow']:
                vulnerabilities.append("HTTP TRACE method enabled")
            if 'PUT' in response.headers['Allow']:
                vulnerabilities.append("HTTP PUT method enabled")

        # Check for security-related headers
        if 'X-Powered-By' in response.headers:
            vulnerabilities.append(
                f"Server exposes software versions via X-Powered-By header: {response.headers['X-Powered-By']}")
        if 'Server' in response.headers:
            vulnerabilities.append(
                f"Server exposes software versions via Server header: {response.headers['Server']}")

        # Check for default pages indicating unconfigured server
        common_pages = [
            'index.html',
            'index.php',
            '/phpinfo.php',
            '/server-status']
        for page in common_pages:
            resp = requests.get(f"{url}/{page}", timeout=10, verify=False)
            if resp.status_code == 200 and 'phpinfo()' in resp.text:
                vulnerabilities.append(f"Exposed phpinfo() at {page}")
            if resp.status_code == 200 and 'Apache Status' in resp.text:
                vulnerabilities.append(
                    f"Apache server status exposed at {page}")

        return vulnerabilities if vulnerabilities else [
            "No known HTTP vulnerabilities detected"]
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

    # Add more checks here (e.g., checking server banner for known vulnerable
    # versions)

    return vulnerabilities if vulnerabilities else [
        "No known FTP vulnerabilities detected"]


def check_smtp_vulnerability(ip_address):
    vulnerabilities = []
    try:
        with smtplib.SMTP(ip_address) as smtp:
            banner = smtp.docmd("NOOP")
            if "220" in banner:
                vulnerabilities.append("SMTP server accessible")

            # Check for open relay
            status, _ = smtp.docmd("MAIL FROM:john@cena.com")
            if "250" in status:
                status, _ = smtp.docmd("RCPT TO:john@cena.com")
                if "250" in status:
                    vulnerabilities.append("Potential open relay detected")

            # Add more checks here for specific SMTP vulnerabilities
    except Exception as e:
        return [f"Error checking SMTP vulnerability: {str(e)}"]

    return vulnerabilities if vulnerabilities else [
        "No known SMTP vulnerabilities detected"]


def check_dns_vulnerability(ip_address):
    vulnerabilities = []
    test_domain = "example.com"  # A domain known to have a substantial DNS record

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip_address]
        answers = resolver.query(test_domain, 'ANY')
        if answers and len(answers) > 1:
            vulnerabilities.append(
                "DNS server is potentially vulnerable to amplification attacks.")
    except dns.exception.DNSException as e:
        if "metaqueries are not allowed" in str(e):
            vulnerabilities.append(
                "DNS server properly configured to disallow metaqueries.")
        else:
            vulnerabilities.append(f"Error checking DNS vulnerability: {e}")

    return vulnerabilities if vulnerabilities else [
        "No known DNS vulnerabilities detected"]


def check_file_sharing_vulnerability(ip_address, port):
    vulnerabilities = []

    # Check for SMBv1 usage (deprecated and insecure)
    try:
        conn_v1 = SMBConnection('', '', 'temp', ip_address, use_ntlm_v2=False)
        if conn_v1.connect(ip_address, port, timeout=10):
            vulnerabilities.append(
                f"SMBv1 protocol is enabled on port {port}, which is outdated and insecure.")
    except Exception as e:
        return [f"Error checking SMBv1 vulnerability: {str(e)}"]

    # Check for misconfigured shares
    try:
        conn = SMBConnection('', '', 'temp', ip_address)
        if conn.connect(ip_address, port, timeout=10):
            shares = conn.listShares(timeout=10)
            for share in shares:
                if share.isSpecial and not share.name.endswith(
                        '$'):  # Non-administrative shares
                    vulnerabilities.append(
                        f"Potentially misconfigured share on port {port}: {share.name}")
    except Exception as e:
        return [f"Error checking share vulnerability: {str(e)}"]

    return vulnerabilities if vulnerabilities else [
        "No known SMB vulnerabilities detected"]


def get_relevant_urls(ip_address, port):
    # Maps specific ports to their commonly associated URLs
    service_urls = {
        3000: [  # Common for Node.js, React, and other web development servers
            f"http://{ip_address}:{port}/admin",
            f"http://{ip_address}:{port}/api",
            f"http://{ip_address}:{port}/dashboard",
            # Add other Node.js/React specific URLs
        ],
        3306: [],  # MySQL - Generally, this port wouldn't serve web pages
        5000: [  # Often used by Flask and other Python web frameworks
            f"http://{ip_address}:{port}/admin",
            f"http://{ip_address}:{port}/login",
            f"http://{ip_address}:{port}/dashboard",
            # Add other Flask specific URLs
        ],
        5432: [],  # PostgreSQL - Typically doesn't serve web pages
        8000: [  # Common alternative HTTP port
            f"http://{ip_address}:{port}/phpmyadmin",
            f"http://{ip_address}:{port}/wordpress",
            f"http://{ip_address}:{port}/webmin",
            # ... other general web service URLs
        ],
        8001: [  # Alternative HTTP port, similar to 8000
            f"http://{ip_address}:{port}/management",
            f"http://{ip_address}:{port}/controlpanel",
            # ... other alternative service URLs
        ],
        8008: [  # Another alternative HTTP port
            f"http://{ip_address}:{port}/server-status",
            f"http://{ip_address}:{port}/server-info",
            # ... other server management URLs
        ],
        8010: [  # Used for HTTP services
            f"http://{ip_address}:{port}/admin",
            f"http://{ip_address}:{port}/status",
            # ... other administrative URLs
        ],
        8080: [  # Frequently used for HTTP services, especially in Java applications
            f"http://{ip_address}:{port}/tomcat/manager",
            f"http://{ip_address}:{port}/jboss/management",
            f"http://{ip_address}:{port}/weblogic/console",
            # ... other Java web server URLs
        ],
        8081: [  # Common alternative to port 8080
            f"http://{ip_address}:{port}/vnc",
            f"http://{ip_address}:{port}/websocket",
            # ... other web services or APIs
        ],
        8443: [  # Commonly used for HTTPS services (SSL/TLS)
            f"https://{ip_address}:{port}/admin",
            f"https://{ip_address}:{port}/secure",
            # ... other secure web service URLs
        ],
        8888: [  # Jupyter Notebook default port
            f"http://{ip_address}:{port}/tree",
            f"http://{ip_address}:{port}/notebooks",
            # ... other Jupyter specific URLs
        ],
        9000: [  # Used by some PHP-FPM installations and development tools
            f"http://{ip_address}:{port}/phpinfo.php",
            f"http://{ip_address}:{port}/phpmyadmin",
            # ... other PHP specific URLs
        ],
        9200: [  # Default port for Elasticsearch
            f"http://{ip_address}:{port}/_cat",
            f"http://{ip_address}:{port}/_search",
            # ... other Elasticsearch specific URLs
        ],
        9300: [],  # Elasticsearch nodes communication, typically not serving web pages
        10000: [  # Webmin - web-based system administration interface
            f"http://{ip_address}:{port}/session_login.cgi",
            f"http://{ip_address}:{port}/config",
            # ... other Webmin specific URLs
        ],
        27017: [],  # MongoDB NoSQL database, typically not serving web pages
    }

    # Default to root if no specific URLs
    return service_urls.get(port, [f"http://{ip_address}:{port}"])


def get_sql_injection_test_urls(ip_address, port):
    # General URLs applicable to most web applications
    general_urls = [
        f"http://{ip_address}:{port}/login",
        f"http://{ip_address}:{port}/admin",
        f"http://{ip_address}:{port}/search",
        f"http://{ip_address}:{port}/query",
        f"http://{ip_address}:{port}/user",
        f"http://{ip_address}:{port}/account",
        # ... other general URLs ...
    ]

    # Port-specific URLs
    port_specific_urls = {
        3000: [  # Node.js, React development servers
            f"http://{ip_address}:{port}/api",
            f"http://{ip_address}:{port}/dev",
            # ... Node.js/React specific URLs ...
        ],
        5000: [  # Flask development server
            f"http://{ip_address}:{port}/flask-admin",
            f"http://{ip_address}:{port}/flask-query",
            # ... Flask specific URLs ...
        ],
        8000: [  # Alternative HTTP port, common for web apps
            f"http://{ip_address}:{port}/config",
            f"http://{ip_address}:{port}/settings",
            # ... HTTP alternative specific URLs ...
        ],
        8080: [  # Frequently used for Java applications
            f"http://{ip_address}:{port}/java-admin",
            f"http://{ip_address}:{port}/servlet",
            f"http://{ip_address}:{port}/jmx-console",
            # ... Java specific URLs ...
        ],
        8443: [  # HTTPS services
            f"https://{ip_address}:{port}/secure",
            f"https://{ip_address}:{port}/ssladmin",
            # ... HTTPS specific URLs ...
        ],
        8888: [  # Jupyter Notebook default port
            f"http://{ip_address}:{port}/notebooks",
            f"http://{ip_address}:{port}/tree",
            # ... Jupyter specific URLs ...
        ],
        9000: [  # PHP-FPM, development tools
            f"http://{ip_address}:{port}/phpinfo",
            f"http://{ip_address}:{port}/php-status",
            # ... PHP specific URLs ...
        ],
        # ... additional port mappings ...
    }

    # Combine general URLs with port-specific URLs if any
    urls_to_test = general_urls + port_specific_urls.get(port, [])
    return urls_to_test


def check_webapp_presence(ip_address, port):
    vulnerabilities = []
    urls_to_test = get_relevant_urls(ip_address, port)
    for url in urls_to_test:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                vulnerabilities.append(f"Web application found at {url}")
        except requests.RequestException:
            # return [f"Error checking webapp vulnerability: {str(e)}"]
            pass

    return vulnerabilities


def check_sql_injection(ip_address, port):
    vulnerabilities = []
    urls_to_test = get_sql_injection_test_urls(
        ip_address, port)  # A subset or specific URLs for SQL tests

    for url in urls_to_test:
        try:
            response = requests.get(
                url + "'", timeout=10)  # Test for SQL Injection
            known_error_indicators = [
                "SQL syntax",
                "database error",
                "mysql_fetch_array",
                "SQLSTATE",
                "ODBC SQL Server Driver"]
            if any(
                    error_indicator in response.text for error_indicator in known_error_indicators):
                vulnerabilities.append(
                    f"Potential SQL Injection vulnerability found at {url}")
        except requests.RequestException:
            pass

    return vulnerabilities


def check_webapp_vulnerability(ip_address, port):
    vulnerabilities = []
    web_vulns = check_webapp_presence(ip_address, port)
    sql_vulns = check_sql_injection(ip_address, port)
    vulnerabilities = web_vulns + sql_vulns

    return vulnerabilities if vulnerabilities else [
        "No known web app vulnerabilities detected"]
