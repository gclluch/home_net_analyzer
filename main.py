# main.py

from home_net_analyzer.scanner import scan_network
from home_net_analyzer.utils import get_mac_details, infer_device_type
from home_net_analyzer.port_scanner import scan_ports, analyze_ports
from home_net_analyzer.os_detector import detect_os_active, detect_os_passive
from home_net_analyzer.vulnerability import scan_vulnerabilities
from home_net_analyzer.traffic_analyzer import start_traffic_analysis, device_traffic
import threading
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log',
    filemode='w'
    )


def main():
    analysis_duration = 14400

    # Start traffic analysis in a separate thread
    # Uncomment the following lines if traffic analysis is implemented and needed
    # traffic_thread = threading.Thread(target=start_traffic_analysis, args=(analysis_duration,))
    # traffic_thread.start()

    # Perform network scanning
    network_range = "192.168.1.0/24"
    devices = scan_network(network_range)
    # print("DEVICES: ", devices)
    # devices = [
    #     {'ip': '192.168.1.100', 'mac': 'e0:d8:c4:a3:67:6e'},
    #     {'ip': '192.168.1.40', 'mac': '78:a0:3f:5f:25:d1'},
    #     {'ip': '192.168.1.121', 'mac': '38:42:0b:6a:fb:bc'}
    # ]
    for device in devices:

        ip = device['ip']
        mac = device['mac']
        manufacturer = get_mac_details(mac)
        open_ports = scan_ports(ip)
        print(open_ports)
        if isinstance(open_ports, dict) and "Error" in open_ports:
            print(f"Error scanning {ip}: {open_ports['Error']}")
            continue

        port_details = analyze_ports(ip, open_ports)
        if "Error" in port_details:
            print(f"Error scanning {ip}: {port_details['Error']}")
            continue

        os_guess = detect_os_active(ip)
        if os_guess.startswith("Unknown OS"):
            os_guess = detect_os_passive(ip)
        device_type = infer_device_type(mac, port_details.keys())
        vulnerabilities = scan_vulnerabilities(ip, port_details.keys())

        print(f"IP: {ip}, MAC: {mac}, Manufacturer: {manufacturer}, OS: {os_guess}, Device Type: {device_type}")
        for port, info in port_details.items():
            print(f"Port: {port}, Service: {info['service']}, Banner: {info['banner']}")
        for port, vuln in vulnerabilities.items():
            print(f"Port: {port}, Vulnerability: {vuln}")

        print()

    # Optionally, you can stop the traffic analysis after a certain duration
    # Uncomment the following lines if traffic analysis is implemented and needed
    # traffic_thread.join()
    # for ip, data in device_traffic.items():
    #     data_regular_dict = {
    #       'total_packets': data['total_packets'],
    #       'protocols': dict(data['protocols']),
    #       'data_volume': data['data_volume'],
    #       'activity_periods': dict(data['activity_periods'])
    #     }
    #     print(f"IP: {ip}, Data: {data_regular_dict}")


if __name__ == "__main__":
    main()
