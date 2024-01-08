"""
Operating System Detection Module

This module contains functions for detecting the operating system of a network device
using both active and passive methods. It leverages the capabilities of the nmap tool
for active scanning and parses p0f logs for passive OS identification.

Functions:
    detect_os_active(ip_address): Actively scans the specified IP address to determine the operating system.
    detect_os_passive(ip_address): Passively determines the operating system from p0f logs based on the IP address.

The module is intended for network analysis and cybersecurity purposes, where identifying
the operating system of network hosts is crucial.
"""
import re
import nmap
import logging


def detect_os_active(ip_address):
    """
    Actively scans the given IP address to identify the operating system.

    This function uses nmap's OS detection capabilities to actively scan the
    specified IP address and guess the operating system.

    Args:
        ip_address (str): The IP address of the target device for OS detection.

    Returns:
        list/str: A list of guessed operating systems or a string 'Unknown OS' if
                  no conclusive OS information is found. Returns 'OS detection failed'
                  if the scanning process encounters an error.
    """
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
    """
    Uses passive methods to infer the operating system of a device from p0f logs.

    The function reads the p0f logs to find entries corresponding to the specified
    IP address and extracts the operating system information, if available.

    Args:
        ip_address (str): The IP address of the target device for passive OS detection.

    Returns:
        str: The inferred operating system from the p0f logs, 'Unknown OS (p0f)' if
             no relevant information is found, or 'p0f OS detection failed' in case
             of an error in processing the logs.
    """
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
