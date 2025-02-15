import nmap
import json

def banner():
    print("""
 ---------------           ----------------
 ---------------           ----------------
 ---------------           ----------------
 ----                      ----
 ----                      ----
 ----     Welcome to       ----
 ----    SecureX V1.0      ----------------
 ----                      ----------------
 ----                      ----------------
 ----                                  ----
 ----                                  ----
 ----                                  ----
 ---------------           ----------------
 ---------------           ----------------
 ---------------           ----------------
    """)

def scan_network(network_range):
    scanner = nmap.PortScanner()
    print(f"Scanning network range: {network_range} ...")
    try:
        scanner.scan(hosts=network_range, arguments='-O -sV')
    except Exception as e:
        print(f"Error: {e}")
        return None

    devices = []
    for host in scanner.all_hosts():
        device_info = {
            'ip': host,
            'hostname': scanner[host].hostname(),
            'os': scanner[host]['osmatch'][0]['name'] if 'osmatch' in scanner[host] and scanner[host]['osmatch'] else "Unknown",
            'services': []
        }

        # Get services and versions
        if 'tcp' in scanner[host]:
            for port, port_data in scanner[host]['tcp'].items():
                service_info = {
                    'port': port,
                    'name': port_data.get('name', 'Unknown'),
                    'product': port_data.get('product', 'Unknown'),
                    'version': port_data.get('version', 'Unknown'),
                }
                device_info['services'].append(service_info)
        devices.append(device_info)

    return devices

def save_results_to_file(data, filename):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)
    print(f"Results saved to {filename}")

if __name__ == "__main__":
    # Display the banner
    banner()

    # Replace with your network range
    network_range = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")

    results = scan_network(network_range)
    if results:
        print("\nScan Results:")
        for device in results:
            print(f"IP: {device['ip']}, Hostname: {device['hostname']}, OS: {device['os']}")
            for service in device['services']:
                print(f"  Port: {service['port']}, Service: {service['name']}, Version: {service['product']} {service['version']}")

        # Save results
        save_results_to_file(results, 'scan_results.json')
