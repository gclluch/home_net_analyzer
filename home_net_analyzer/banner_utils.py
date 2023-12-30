import socket
import http.client
import ssl
import ftplib
import smtplib
import paramiko

# Only disable on secure, internal networks
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(ip_address, port, context=context, timeout=10)
        conn.request("GET", "/")
        response = conn.getresponse()
        return f"{response.status} {response.reason}"
    except Exception as e:
        return f"Failed to retrieve HTTPS banner: {str(e)}"


def grab_banner_ftp(ip_address, port):
    try:
        with ftplib.FTP() as ftp:
            ftp.connect(ip_address, port, timeout=10)
            banner = ftp.getwelcome()
            return banner
    except Exception as e:
        return f"Failed to retrieve FTP banner: {str(e)}"


def grab_banner_ssh(ip_address, port):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip_address, port=port, username='invalid', password='invalid', timeout=10)
    except paramiko.ssh_exception.SSHException as e:
        return str(e)  # Often contains the banner information
    except Exception as e:
        return f"Failed to retrieve SSH banner: {str(e)}"


def grab_banner_smtp(ip_address, port):
    try:
        with smtplib.SMTP(ip_address, port, timeout=10) as smtp:
            banner = smtp.docmd("NOOP")
            return str(banner)
    except Exception as e:
        return f"Failed to retrieve SMTP banner: {str(e)}"