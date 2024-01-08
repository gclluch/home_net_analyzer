"""
Banner Grabbing Utilities Module

This module contains functions for grabbing banners from various services over HTTP.
It is designed to be used as part of a larger network scanning tool to gather information
about the services running on a network. It includes functionality for fetching banners
from standard HTTP and HTTPS services, as well as for more specific services like FTP, SSH,
SMTP, MQTT, IPP, and others. The module also handles application fingerprinting by analyzing
the content of HTTP responses.

Functions:
    grab_banner_http(ip_address, port): Retrieve HTTP banner information.
    grab_banner_https(ip_address, port): Retrieve HTTPS banner information.
    grab_banner_ftp(ip_address, port): Retrieve FTP banner information.
    grab_banner_ssh(ip_address, port): Retrieve SSH banner information.
    grab_banner_smtp(ip_address, port): Retrieve SMTP banner information.
    probe_mqtt_broker(ip_address, port): Probe MQTT broker responsiveness.
    grab_printer_banner(ip_address, port): Retrieve banner information for IPP.
    (Other functions as defined in the module)

This module is part of a network scanning tool aimed at security analysis and network management.

Dependencies: requests, http.client, ssl, ftplib, smtplib, paramiko, paho.mqtt,
(other dependencies as applicable)
"""
import socket
import ssl
import http.client
import ftplib
import smtplib
import poplib
import imaplib
import dns.resolver
import dns.query
import paho.mqtt.client as mqtt

# Only disable on secure, internal networks
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def grab_banner_http(ip_address, port):
    """
    Retrieve HTTP banner information from the specified IP address and port.

    Args:
        ip_address (str): The IP address to connect to.
        port (int): The port number to connect to.

    Returns:
        dict: A dictionary containing banner information or an error message.
    """
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Banner Grabber)'}
        conn = http.client.HTTPConnection(ip_address, port, timeout=10)
        conn.request("GET", "/", headers=headers)
        response = conn.getresponse()

        banner_info = {
            'status': f"{response.status} {response.reason}",
            'server': response.headers.get('Server', 'Unknown Server'),
            'x_powered_by': response.headers.get('X-Powered-By', 'Not disclosed'),
            # Additional headers can be added here
        }

        # Handling redirects if necessary
        if response.status in [301, 302]:
            banner_info['location'] = response.getheader('Location')

        # Fetch and analyze content for fingerprinting
        content = response.read().decode('utf-8', errors='ignore')
        banner_info['application_fingerprint'] = analyze_content(content)

        return banner_info
    except Exception as e:
        return {'error': f"Failed to retrieve banner: {str(e)}"}


def analyze_content(content):
    """
    Analyzes the given content of a web page to identify the underlying technologies.

    This function searches the content for specific patterns or keywords that indicate
    the use of particular content management systems (CMS), web frameworks, server-side
    languages, or other notable technologies. It compiles these findings into a
    fingerprint dictionary.

    Args:
        content (str): The HTML content of a web page to analyze.

    Returns:
        str: A string representation of the application's fingerprint.
        It lists detected technologies and their characteristics.
        Returns a message indicating no specific technologies were detected
        if none are found in the content.
    """
    fingerprint = {}

    # CMS Detection
    if 'wp-content' in content:
        fingerprint['cms'] = 'WordPress'
    elif '/media/system/js/' in content:
        fingerprint['cms'] = 'Joomla'
    elif 'Drupal' in content:
        fingerprint['cms'] = 'Drupal'

    # Frameworks and Libraries
    if 'angular.min.js' in content:
        fingerprint['framework'] = 'AngularJS'
    elif 'react' in content:
        fingerprint['framework'] = 'React'
    elif 'vue.min.js' in content:
        fingerprint['framework'] = 'Vue.js'

    # Server-Side Languages
    if '<?php' in content:
        fingerprint['server_lang'] = 'PHP'
    elif 'asp.net' in content.lower():
        fingerprint['server_lang'] = 'ASP.NET'

    # Specific File Paths or Unique Identifiers
    if '/.env' in content:
        fingerprint['sensitive_file'] = 'Exposed .env File'
    if 'X-Powered-By: Express' in content:
        fingerprint['express_app'] = 'Express.js'

    # Convert the fingerprint dictionary to a string for easy display
    return ', '.join([f"{key}: {value}" for key, value in fingerprint.items(
    )]) if fingerprint else "No specific fingerprint detected"


def grab_banner_https(ip_address, port):
    """
    Retrieves HTTPS banner information from the specified IP address and port.

    Args:
        ip_address (str): The IP address of the server to connect to.
        port (int): The port number to use for the HTTPS connection.

    Returns:
        dict: A dictionary containing the HTTPS banner information, server details,
              and SSL certificate information. Returns an error message if the
              retrieval fails.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        conn = http.client.HTTPSConnection(ip_address, port, context=context, timeout=10)
        conn.request("GET", "/")
        response = conn.getresponse()

        banner_info = {
            'status': f"{response.status} {response.reason}",
            'server': response.headers.get('Server', 'Unknown Server'),
            'ssl_certificate': get_ssl_certificate_info(conn.sock),
        }

        conn.close()
        return banner_info
    except Exception as e:
        return {"error": f"Failed to retrieve HTTPS banner: {str(e)}"}


def get_ssl_certificate_info(connection):
    """
    Extracts and returns SSL certificate information from the given connection.

    Args:
        connection (ssl.SSLSocket): The SSL socket connection to extract certificate info from.

    Returns:
        dict: A dictionary containing details about the SSL certificate,
              including issuer, validity period, and subject.
    """
    certificate = connection.getpeercert()
    if not certificate:
        return "No certificate information available"

    def format_name(name):
        return ', '.join(f"{name_part[0]}={name_part[1]}" for name_part in name)

    issuer = format_name(certificate.get('issuer'))
    valid_from = certificate.get('notBefore')
    valid_to = certificate.get('notAfter')
    subject = format_name(certificate.get('subject'))

    return {
        'issuer': issuer,
        'valid_from': valid_from,
        'valid_to': valid_to,
        'subject': subject
    }


def grab_banner_dns(ip_address, port):
    """
    Retrieves DNS banner information from the specified IP address and port.

    Args:
        ip_address (str): The IP address of the DNS server.
        port (int): The port number of the DNS service.

    Returns:
        dict: A dictionary containing the response with DNS version information,
              or an error message if the retrieval fails.
    """
    try:
        query = dns.message.make_query(
            'version.bind', dns.rdatatype.TXT, dns.rdataclass.CH)
        response = dns.query.udp(query, ip_address, port=port, timeout=10)
        if response.answer:
            return {'response': str(response.answer[0])}
        else:
            return {'response': "No version information available"}
    except Exception as e:
        return {'error': f"Failed to probe DNS service: {str(e)}"}


def grab_banner_ftp(ip_address, port):
    """
    Retrieves FTP banner and additional server information.

    Args:
        ip_address (str): The IP address of the FTP server.
        port (int): The port number of the FTP service.

    Returns:
        dict: A dictionary containing FTP server information, including welcome
              banner, feature list, and help information, or an error message if
              the retrieval fails.
    """
    try:
        with ftplib.FTP(timeout=10) as ftp:
            ftp.connect(ip_address, port)
            welcome_banner = ftp.getwelcome()

            # Fetch additional information
            feature_list = ftp.sendcmd("FEAT")
            help_info = ftp.sendcmd("HELP")

            return {
                "welcome_banner": welcome_banner,
                "feature_list": feature_list,
                "help_info": help_info
            }
    except ftplib.all_errors as e:
        return {"error": f"Failed to retrieve FTP banner: {str(e)}"}


def grab_banner_ssh(ip_address, port):
    """
    Retrieves the SSH banner from the specified IP address and port.

    Args:
        ip_address (str): The IP address of the SSH server.
        port (int): The port number of the SSH service.

    Returns:
        dict: A dictionary containing the SSH banner response, or an error message
              if the retrieval fails.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ip_address, port))

        # Receive the banner
        banner = s.recv(1024).decode('utf-8').strip()
        s.close()
        return {'response': banner}
    except socket.error as e:
        return {'error': f"Socket error: {str(e)}"}
    except Exception as e:
        return {'error': f"Failed to retrieve SSH banner: {str(e)}"}


def grab_banner_smtp(ip_address, port):
    """
    Retrieves the SMTP banner from the specified IP address and port.

    Args:
        ip_address (str): The IP address of the SMTP server.
        port (int): The port number of the SMTP service.

    Returns:
        dict: A dictionary containing the SMTP response code and message, or an
              error message if the retrieval fails.
    """
    try:
        with smtplib.SMTP(ip_address, port, timeout=10) as smtp:
            # The connect method implicitly fetches the banner
            smtp_banner = smtp.docmd("NOOP")

            # Extracting the response code and message from the banner
            banner_info = {
                'response_code': smtp_banner[0],
                'message': smtp_banner[1]
            }
            return banner_info
    except Exception as e:
        return {'error': f"Failed to retrieve SMTP banner: {str(e)}"}


def probe_mqtt_broker(ip_address, port):
    """
    Probes an MQTT broker to check its responsiveness.

    Args:
        ip_address (str): The IP address of the MQTT broker.
        port (int): The port number on which the MQTT broker is running.

    Returns:
        dict: A dictionary containing a response message if the MQTT broker is
              responsive, or an error message if the probe fails.
    """
    try:
        client = mqtt.Client()
        client.connect(ip_address, port, 60)
        client.disconnect()
        return {'response': "MQTT broker responsive."}
    except Exception as e:
        return {'error': f"Failed to probe MQTT broker: {str(e)}"}


def grab_banner_pop3(ip_address, port):
    """
    Retrieves the POP3 banner from the specified IP address and port.

    Args:
        ip_address (str): The IP address of the POP3 server.
        port (int): The port number of the POP3 service.

    Returns:
        dict: A dictionary containing the POP3 banner, or an error message
              if the retrieval fails.
    """
    try:
        server = poplib.POP3(ip_address, port, timeout=10)
        banner = server.getwelcome()
        server.quit()
        return {'response': banner}
    except Exception as e:
        return {'error': f"Failed to retrieve POP3 banner: {str(e)}"}


def grab_banner_imap(ip_address, port):
    """
    Retrieves the IMAP banner from the specified IP address and port.

    Args:
        ip_address (str): The IP address of the IMAP server.
        port (int): The port number of the IMAP service.

    Returns:
        dict: A dictionary containing the IMAP banner, or an error message
              if the retrieval fails.
    """
    try:
        server = imaplib.IMAP4(ip_address, port)
        banner = server.welcome
        server.logout()
        return {'response': banner}
    except Exception as e:
        return {'error': f"Failed to retrieve IMAP banner: {str(e)}"}


def grab_printer_banner(ip_address, port):
    # Assuming grab_banner_http returns a dictionary
    return grab_banner_http(ip_address, port)
