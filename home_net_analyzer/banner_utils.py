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
        banner_info['content'] = content
        # banner_info['application_fingerprint'] = analyze_content(content)

        return banner_info
    except Exception as e:
        return {'error': f"Failed to retrieve banner: {str(e)}"}


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


def get_ssl_certificate_info(sock):
    cert_info = ssl.DER_cert_to_PEM_cert(sock.getpeercert(binary_form=True))
    certificate = ssl.PEM_cert_to_DER_cert(cert_info)

    # Extracting details from the certificate
    details = {
        'issuer': certificate.get_issuer(),
        'valid_from': certificate.get_notBefore(),
        'valid_to': certificate.get_notAfter(),
        'subject': certificate.get_subject(),
    }

    # Formatting dates
    details['valid_from'] = datetime.strptime(details['valid_from'].decode('ascii'), '%Y%m%d%H%M%SZ')
    details['valid_to'] = datetime.strptime(details['valid_to'].decode('ascii'), '%Y%m%d%H%M%SZ')

    return details


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