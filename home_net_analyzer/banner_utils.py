import http.client
import dns.resolver
import socket
import ssl
from datetime import datetime
import ftplib
import smtplib
import paramiko
import paho.mqtt.client as mqtt


# Only disable on secure, internal networks
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def grab_banner_http(ip_address, port):
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

        # Handling redirects
        if response.status in [301, 302]:
            banner_info['location'] = response.getheader('Location')

        # Fetch and analyze content for fingerprinting (if necessary)
        content = response.read().decode('utf-8', errors='ignore')
        banner_info['application_fingerprint'] = analyze_content(content)

        return banner_info
    except Exception as e:
        return {'error': f"Failed to retrieve banner: {str(e)}"}


def analyze_content(content):
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
    return ', '.join([f"{key}: {value}" for key, value in fingerprint.items()]) if fingerprint else "No specific fingerprint detected"



def grab_banner_https(ip_address, port):
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
    certificate = connection.getpeercert()
    if not certificate:
        return "No certificate information available"

    issuer = certificate.get('issuer')
    valid_from = certificate.get('notBefore')
    valid_to = certificate.get('notAfter')
    subject = certificate.get('subject')

    # Additional formatting and processing can be done here

    return {
        'issuer': issuer,
        'valid_from': valid_from,
        'valid_to': valid_to,
        'subject': subject
    }


def grab_banner_ftp(ip_address, port):
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
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ip_address, port))

        # Receive the banner
        banner = s.recv(1024).decode('utf-8').strip()
        s.close()
        return {'response': banner}  # Return a dictionary for consistency
    except socket.error as e:
        return {'error': f"Socket error: {str(e)}"}
    except Exception as e:
        return {'error': f"Failed to retrieve SSH banner: {str(e)}"}


def grab_banner_smtp(ip_address, port):
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


def probe_dns_server(ip_address, port):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip_address]
        resolver.port = port
        answers = resolver.query('example.com', 'A')
        if answers:
            return {'response': "DNS service is responsive."}
    except Exception as e:
        return {'error': f"Failed to probe DNS service: {str(e)}"}


def probe_mqtt_broker(ip_address, port):
    try:
        client = mqtt.Client()
        client.connect(ip_address, port, 60)
        client.disconnect()
        return {'response': "MQTT broker responsive."}
    except Exception as e:
        return {'error': f"Failed to probe MQTT broker: {str(e)}"}


def grab_printer_banner(ip_address, port):
    # Assuming grab_banner_http returns a dictionary
    return grab_banner_http(ip_address, port)