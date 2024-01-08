# main.py

from home_net_analyzer.scanner import scan_network
from home_net_analyzer.device_utils import get_mac_details, infer_device_type
from home_net_analyzer.port_scanner import scan_ports, analyze_ports, scan_ports_2
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
    print("DEVICES: ", devices)

    for device in devices:
        ip = device['ip']
        # print('DEVICE: ', device)

        if ip in [
            # '192.168.1.1',
            # '192.168.1.74',
            # '192.168.1.169',
            '192.168.1.21'
            ]:
            continue
        mac = device['mac']
        manufacturer = get_mac_details(mac)

        scan_results = scan_ports(ip)

        port_details = {}
        if scan_results:
            port_details = analyze_ports(ip, scan_results)

        # print(port_details)
        if "Error" in port_details:
            print(f"Error analyzing {ip}: {port_details['Error']}")
            # continue

        vulnerabilities = {}
        if port_details:
            vulnerabilities = scan_vulnerabilities(ip, port_details.keys())


        os_guess = detect_os_active(ip)
        # print('detect_os_active')
        if os_guess.startswith("Unknown OS"):
            os_guess = detect_os_passive(ip)

        device_type = infer_device_type(mac, port_details.keys())

        print("\n" + "="*50)
        print(f"Device Information for IP: {ip}")
        print("="*50)
        print(f"  MAC Address: {mac}")
        print(f"  Manufacturer: {manufacturer}")
        print(f"  OS (Guess): {os_guess}")
        print(f"  Device Type: {device_type}")
        print("\n  Open Ports and Services:")
        if not port_details:
            print("    No TCP ports found.")
        for port, info in port_details.items():
            print(f"    Port: {port}")
            print(f"      Service: {info['service']}")
            # print(f"      Banner: {info['banner']}")
            print(f"      Banner: {info['banner']}")

        if vulnerabilities:
            print("\n  Identified Vulnerabilities:")
        for port, vuln in vulnerabilities.items():
            print(f"    Port: {port}, Vulnerabilities:")
            for v in vuln:  # Assuming vuln is a list of vulnerabilities
                print(f"      - {v}")
        print("="*50 + "\n")

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
