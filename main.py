# main.py

from network_scanner import scan_network, get_mac_details, scan_ports, detect_os_active, detect_os_passive, infer_device_type, scan_vulnerabilities, analyze_ports
from traffic_analyzer import start_traffic_analysis, device_traffic
import threading


def main():
    analysis_duration = 14400  #

    # Start traffic analysis in a separate thread
    # traffic_thread = threading.Thread(target=start_traffic_analysis, args=(analysis_duration,))
    # traffic_thread.start()

    # Perform network scanning
    network_range = "192.168.1.0/24"
    devices = scan_network(network_range)

    for device in devices:
        ip = device['ip']
        mac = device['mac']
        manufacturer = get_mac_details(mac)
        open_ports = scan_ports(ip)
        open_ports = analyze_ports(ip, open_ports)
        if "Error" in open_ports:
            print(f"Error scanning {ip}: {open_ports['Error']}")
            continue
        os_guess = detect_os_active(ip)
        if os_guess.startswith("Unknown OS"):
            # If active detection fails, try passive detection
            os_guess = detect_os_passive(ip)
        device_type = infer_device_type(mac, open_ports.keys())
        vulnerabilities = scan_vulnerabilities(ip, open_ports.keys())


        if "Error" in open_ports:
            print(f"Error scanning {ip}: {open_ports['Error']}")
            continue

        print(f"IP: {ip}, MAC: {mac}, Manufacturer: {manufacturer}, OS: {os_guess}, Device Type: {device_type}")
        for port, info in open_ports.items():
            print(f"Port: {port}, Service: {info['service']}, Banner: {info['banner']}")
        for port, vuln in vulnerabilities.items():
            print(f"Port: {port}, Vulnerability: {vuln}")

        print()


    # Optionally, you can stop the traffic analysis after a certain duration

    # traffic_thread.join()
    # # Display traffic analysis data
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
