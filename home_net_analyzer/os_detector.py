# os_detector.py
import nmap

def detect_os_active(ip_address):
    nm = nmap.PortScanner()
    # print(1)
    try:
        nm.scan(ip_address, arguments="-A")  # Using -O for OS detection
        # print(1)
        if 'osclass' in nm[ip_address]:
            for osclass in nm[ip_address]['osclass']:
                return osclass.get('osfamily', 'Unknown') + " " + osclass.get('osgen', '')
        return "Unknown OS"
    except Exception as e:
        return f"OS detection failed: {str(e)}"


# def detect_os_passive(ip_address):
#     try:
#         with open('/tmp/p0f.log', 'r') as file:
#             for line in file:
#                 if ip_address in line and "os=" in line:
#                     parts = line.split('os=')
#                     if len(parts) > 1:
#                         os_info = parts[1].split('|')[0]
#                         return os_info.strip()
#         return "Unknown OS (p0f)"
#     except Exception as e:
#         return f"p0f OS detection failed: {str(e)}"


def detect_os_passive(ip_address):
    try:
        os_counts = {}
        with open('/tmp/p0f.log', 'r') as file:
            for line in file:
                if ip_address in line and "os=" in line:
                    parts = line.split('os=')
                    if len(parts) > 1:
                        os_info = parts[1].split('|')[0].strip()
                        os_counts[os_info] = os_counts.get(os_info, 0) + 1
        if not os_counts:
            return "Unknown OS (p0f)"

        most_likely_os = max(os_counts, key=os_counts.get)
        return most_likely_os
    except Exception as e:
        return f"p0f OS detection failed: {str(e)}"
