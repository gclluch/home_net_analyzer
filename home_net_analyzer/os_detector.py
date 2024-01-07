# os_detector.py
import re
import nmap
import logging


def detect_os_active(ip_address):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip_address, arguments="-O --osscan-guess")  # Focused on OS detection
        if 'osclass' in nm[ip_address]:
            # Handling multiple OS guesses
            os_guesses = [osclass.get('osfamily', 'Unknown') + " " + osclass.get('osgen', '') for osclass in nm[ip_address]['osclass']]
            return os_guesses if os_guesses else "Unknown OS"
        else:
            return "Unknown OS"
    except Exception as e:
        logging.error(f"OS detection failed for {ip_address}: {str(e)}")
        return "OS detection failed"


def detect_os_passive(ip_address):
    try:
        with open('/tmp/p0f.log', 'r') as file:
            lines = file.readlines()
            # Reverse the list to start from the most recent entry
            for line in reversed(lines):
                if ip_address in line:
                    match = re.search(r'os=([^|]+)', line)
                    if match:
                        return match.group(1).strip()
            return "Unknown OS (p0f)"
    except Exception as e:
        logging.error(f"Passive OS detection failed: {str(e)}")
        return "p0f OS detection failed"
