EXTENDED_COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    # ... additional ports and services as needed ...
}

KNOWN_ROUTER_OUIS = {
    "00:40:96": "Cisco Systems",
    "00:09:5B": "Netgear",
    "00:05:5D": "D-Link Systems",
    "14:CC:20": "TP-Link",
    "00:11:50": "Belkin",
    "44:37:E6": "Hon Hai Precision (Foxconn)",
    "00:1A:92": "ASUSTek Computer",
    "00:17:9A": "Broadcom",
    "00:0C:29": "VMware",
    "00:1C:F0": "D-Link",
    "58:6D:8F": "Cisco Meraki",
    "F0:9F:C2": "Ubiquiti Networks",
    # ... add more as needed ...
}

WEBAPP_PORTS = [
    3000,  # Often used by Node.js and React development servers
    3306,  # Default MySQL database port
    5000,  # Commonly used by Flask development server
    5432,  # Default PostgreSQL database port
    8000,  # Often used as an alternative for HTTP services
    8001,  # Alternative HTTP services or secondary interfaces
    8008,  # Similar to port 8001, alternative HTTP services
    8010,  # Another port for alternative HTTP services
    8080,  # Frequently used for HTTP services, especially in development environments
    8081,  # Common alternative to port 8080
    8443,  # Commonly used for HTTPS services (alternative to port 443)
    8888,  # Jupyter Notebook default port
    9000,  # Used by some PHP-FPM installations and development tools
    9200,  # Default port for Elasticsearch
    9300,  # Elasticsearch nodes communication
    10000, # Webmin - web-based system administration interface
    27017, # Default MongoDB NoSQL database port
]