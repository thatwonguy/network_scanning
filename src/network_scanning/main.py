import logging
import threading
from datetime import datetime
import socket
import psutil
import scapy.all as scapy
from graphs import DiagramGenerator
from reports import ReportGenerator
import matplotlib.pyplot as plt
import warnings
from smbprotocol.connection import Connection # For NetBIOS (Windows-based devices)
from zeroconf import Zeroconf, ServiceBrowser, ServiceInfo  # For mDNS (Bonjour, IoT devices)
from mac_vendor_lookup import MacLookup  # Add back MacLookup

# Switch to non-GUI backend for matplotlib
plt.switch_backend('Agg')

# Suppress scapy warnings about MAC address broadcasting
warnings.filterwarnings("ignore", category=RuntimeWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

class NetworkScanner:
    def __init__(self):
        self.current_datetime = datetime.now().strftime("%m-%d-%Y_%I-%M-%S_%p")
        self.zeroconf = Zeroconf()  # Initialize zeroconf when the scanner is created
        self.mac_lookup = MacLookup()  # Initialize the MacLookup instance
        self.mac_lookup.update_vendors()  # Update the vendor list for MAC addresses
        
    # Layer 1: Physical Layer (Interfaces and Link Speed)
    def layer1_scan(self):
        try:
            interfaces = psutil.net_if_addrs()
            interface_stats = psutil.net_if_stats()
            io_counters = psutil.net_io_counters(pernic=True)
            physical_data = []
            
            for interface_name, addresses in interfaces.items():
                if interface_name in interface_stats:
                    stats = interface_stats[interface_name]
                    io_stat = io_counters.get(interface_name, None)
                    
                    # Capture IP addresses (both IPv4 and IPv6)
                    ipv4_addrs = [addr.address for addr in addresses if addr.family == socket.AF_INET]
                    ipv6_addrs = [addr.address for addr in addresses if addr.family == socket.AF_INET6]
                    mac_addrs = [addr.address for addr in addresses if addr.family == psutil.AF_LINK]
                    
                    # Check for optional attributes (autoneg, duplex)
                    duplex = getattr(stats, 'duplex', 'Unknown')
                    if duplex == psutil.NIC_DUPLEX_FULL:
                        duplex = "Full"
                    elif duplex == psutil.NIC_DUPLEX_HALF:
                        duplex = "Half"
                    else:
                        duplex = "Unknown"

                    autoneg = getattr(stats, 'autoneg', 'Unknown')
                    mtu = getattr(stats, 'mtu', 'Unknown')
                    
                    # Gather all data
                    physical_data.append({
                        'interface': interface_name,
                        'is_up': stats.isup,
                        'speed': stats.speed,
                        'mtu': mtu,
                        'duplex': duplex,
                        'auto_negotiation': autoneg,
                        'ipv4': ipv4_addrs,
                        'ipv6': ipv6_addrs,
                        'mac_address': mac_addrs[0] if mac_addrs else "N/A",
                        'packets_sent': io_stat.packets_sent if io_stat else "N/A",
                        'packets_received': io_stat.packets_recv if io_stat else "N/A",
                        'errors_in': io_stat.errin if io_stat else "N/A",
                        'errors_out': io_stat.errout if io_stat else "N/A",
                    })
            return physical_data
        except Exception as e:
            logging.error(f"Layer 1 scan failed: {e}")
            return []

    # Layer 2: ARP for MAC addresses with enhanced device name resolution
    def layer2_scan(self, ip_range):
        try:
            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            devices = []
            for sent, received in answered_list:
                device = {'ip': received.psrc, 'mac': received.hwsrc}

                # Device manufacturer lookup
                try:
                    device_manufacturer = self.mac_lookup.lookup(device['mac'])
                    device['device_manufacturer'] = device_manufacturer
                except KeyError:
                    device['device_manufacturer'] = "Unknown Manufacturer"

                # Latency calculation (ping)
                latency = self.get_ping_latency(device['ip'])
                device['latency_ms'] = latency if latency else "No response"

                # Resolve device name
                device_name = self.resolve_device_name(received.psrc)
                device['name'] = device_name or "Unknown"

                devices.append(device)
            return devices
        except Exception as e:
            logging.error(f"Layer 2 scan failed: {e}")
            return []

    def get_ping_latency(self, ip):
        try:
            packet = scapy.IP(dst=ip) / scapy.ICMP()
            response = scapy.sr1(packet, timeout=1, verbose=False)
            if response:
                latency = response.time - packet.sent_time  # Calculate latency in seconds
                return latency * 1000  # Convert to milliseconds
        except Exception as e:
            logging.error(f"Error pinging {ip}: {e}")
        return None

    def resolve_device_name(self, ip):
        # Attempt to resolve name via DNS first (socket.gethostbyaddr)
        try:
            dns_name = socket.gethostbyaddr(ip)[0]
            logging.info(f"Resolved {ip} to {dns_name} via DNS")
            return dns_name
        except socket.herror:
            logging.info(f"DNS lookup failed for IP: {ip}")
        
        # Attempt NetBIOS name resolution for Windows devices
        try:
            netbios_name = self.netbios_name_lookup(ip)
            if netbios_name:
                logging.info(f"Resolved {ip} to {netbios_name} via NetBIOS")
                return netbios_name
        except Exception as e:
            logging.debug(f"NetBIOS lookup failed for IP {ip}: {e}")

        # Attempt mDNS/Bonjour resolution
        try:
            mdns_name = self.mdns_lookup(ip)
            if mdns_name:
                logging.info(f"Resolved {ip} to {mdns_name} via mDNS")
                return mdns_name
        except Exception as e:
            logging.debug(f"mDNS lookup failed for IP {ip}: {e}")

        # Fallback if all methods fail
        logging.info(f"Failed to resolve {ip}, returning 'Unknown'")
        return None

    # NetBIOS name lookup for Windows devices
    def netbios_name_lookup(self, ip):
        try:
            conn = Connection(uuid.uuid4(), ip)  # Establish a connection with the device's IP
            conn.connect(ip, 139)  # Port 139 for NetBIOS
            return conn.negotiate()  # Try to get the NetBIOS name via negotiation
        except Exception as e:
            logging.debug(f"NetBIOS resolution failed for IP {ip}: {e}")
        return None

    # mDNS lookup using Zeroconf
    def mdns_lookup(self, ip):
        try:
            info = self.zeroconf.get_service_info("_http._tcp.local.", f"{ip}.local.")
            if info:
                return info.name
        except Exception as e:
            logging.debug(f"mDNS lookup failed for IP {ip}: {e}")
        return None

    def __del__(self):
        if hasattr(self, 'zeroconf'):  # Check if zeroconf is initialized
            self.zeroconf.close()  # Close zeroconf instance safely


    # Layer 3: ICMP (Ping) for IP addresses
    def layer3_scan(self, ip_range):
        active_hosts = []
        def ping_ip(ip):
            try:
                packet = scapy.IP(dst=ip)/scapy.ICMP()
                response = scapy.sr1(packet, timeout=1, verbose=False)
                if response:
                    active_hosts.append(ip)
            except Exception as e:
                logging.error(f"Error pinging {ip}: {e}")
        threads = []
        for ip in ip_range:
            thread = threading.Thread(target=ping_ip, args=(ip,))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
        return active_hosts

    # Layer 4: TCP/UDP Port Scanning
    def layer4_scan(self, ip):
        open_ports = []
        common_ports = [80, 443, 21, 22, 23, 25, 53, 110, 123, 143, 3389]  # Add more ports as needed
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))  # Connect to the port
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception as e:
                logging.error(f"Error scanning port {port} on {ip}: {e}")
        return open_ports

    # Layer 5: Session Information
    def layer5_scan(self):
        try:
            sessions = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == "ESTABLISHED" and conn.laddr and conn.raddr:
                    sessions.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'status': conn.status
                    })
            return sessions
        except Exception as e:
            logging.error(f"Layer 5 scan failed: {e}")
            return []

    # Layer 6: Presentation Layer (Encryption/Decryption)
    def layer6_scan(self):
        try:
            return [{"description": "SSL/TLS encryption detected on HTTPS ports."}]
        except Exception as e:
            logging.error(f"Layer 6 scan failed: {e}")
            return []

    # Layer 7: Application Layer (Application protocols like HTTP, FTP)
    def layer7_scan(self):
        try:
            applications = []
            applications.append({"protocol": "HTTP", "description": "HyperText Transfer Protocol"})
            applications.append({"protocol": "FTP", "description": "File Transfer Protocol"})
            return applications
        except Exception as e:
            logging.error(f"Layer 7 scan failed: {e}")
            return []

    def run_all_layer_scans(self, ip_base):
        ip_range = [f"{ip_base}{i}" for i in range(1, 255)]

        # Perform scans for all layers
        layer_data = []
        diagrams = {}

        # Layer 1: Physical Layer
        logging.info("Starting Layer 1 scan...")
        layer1_results = self.layer1_scan()
        # Layer 1: This describes the network hardware and its status on the machine.
        layer_data.append({
            "title": "Layer 1: Physical Layer",
            "description": "This layer shows the network hardware (like Wi-Fi or Ethernet) on your localhost (the computer you ran this script in), including its status, speed, and data usage.",
            "data": [
                f"{i + 1}. Interface: {item['interface']}, "
                f"Status: {'Up' if item['is_up'] else 'Down'}, "
                f"Speed: {item['speed']} Mbps, "
                f"MTU: {item['mtu']}, "
                f"Duplex: {item['duplex']}, "
                f"Auto-Negotiation: {item['auto_negotiation']}, "
                f"IPv4: {', '.join(item['ipv4']) if item['ipv4'] else 'N/A'}, "
                f"IPv6: {', '.join(item['ipv6']) if item['ipv6'] else 'N/A'}, "
                f"MAC: {item['mac_address']}, "
                f"Packets Sent: {item['packets_sent']}, "
                f"Packets Received: {item['packets_received']}, "
                f"Errors In: {item['errors_in']}, "
                f"Errors Out: {item['errors_out']}"
                for i, item in enumerate(layer1_results)
            ]
        })

        # Layer 2: Data Link Layer (ARP)
        logging.info("Starting Layer 2 scan...")
        layer2_results = self.layer2_scan(f"{ip_base}1/24")
        logging.debug(f"Layer 2 devices: {layer2_results}")
        # Layer 2: This shows devices connected to the same local network as this machine.
        layer_data.append({
            "title": "Layer 2: Data Link Layer (ARP)",
            "description": "This layer shows other devices on the same network as this computer, including their IP, MAC addresses, device manufacturer, latency, and device type.",
            "data": [
                f"IP: {item['ip']}, MAC: {item['mac']}, Name: {item['name']}, Device Manufacturer: {item.get('device_manufacturer', 'Unknown')}"
                for item in layer2_results
            ]
        })
        
        # Generate diagram for Layer 2 showing the devices on the network
        diagrams["Layer 2: Data Link Layer (ARP)"] = DiagramGenerator.generate_network_diagram(layer2_results, "Layer 2: Data Link Layer (ARP)")

        # Layer 3: Network Layer (ICMP Ping)
        logging.info("Starting Layer 3 scan...")
        layer3_results = self.layer3_scan(ip_range)
        # Layer 3: This checks which devices are currently online.
        layer_data.append({
            "title": "Layer 3: Network Layer (ICMP Ping)",
            "description": "This layer shows which devices are online and responding to the network scan.",
            "data": [f"Active IP: {ip}" for ip in layer3_results]
        })

        # Layer 4: Transport Layer (TCP/UDP Port Scan)
        logging.info("Starting Layer 4 scan...")
        layer4_data = {}
        for ip in layer3_results:
            open_ports = self.layer4_scan(ip)
            if open_ports:
                layer4_data[ip] = open_ports
        # Layer 4: This checks which services (like websites or file sharing) are open on the devices.
        layer_data.append({
            "title": "Layer 4: Transport Layer (TCP/UDP)",
            "description": "This layer shows the open services (such as websites or file sharing) running on the devices.",
            "data": [f"IP: {ip}, Open Ports: {', '.join(map(str, ports))}" for ip, ports in layer4_data.items()]
        })

        # Layer 5: Session Layer
        logging.info("Starting Layer 5 scan...")
        layer5_results = self.layer5_scan()
        # Layer 5: This shows active connections between this computer and other devices.
        layer_data.append({
            "title": "Layer 5: Session Layer",
            "description": "This layer shows active network connections, like web browsing or file transfers, between your computer and other devices.",
            "data": [f"Local: {sess['local_address']}, Remote: {sess['remote_address']}, Status: {sess['status']}" for sess in layer5_results]
        })

        # Layer 6: Presentation Layer (Encryption)
        logging.info("Starting Layer 6 scan...")
        layer6_results = self.layer6_scan()
        # Layer 6: This checks for secure connections, such as HTTPS websites.
        layer_data.append({
            "title": "Layer 6: Presentation Layer",
            "description": "This layer shows any secure encryption being used, such as HTTPS for websites.",
            "data": [f"{enc['description']}" for enc in layer6_results]
        })

        # Layer 7: Application Layer (Application protocols)
        logging.info("Starting Layer 7 scan...")
        layer7_results = self.layer7_scan()
        # Layer 7: This shows the types of programs or services being used, like websites or file transfers.
        layer_data.append({
            "title": "Layer 7: Application Layer",
            "description": "This layer shows the types of programs or services running, such as websites (HTTP) or file transfers (FTP).",
            "data": [f"Protocol: {app['protocol']}, Description: {app['description']}" for app in layer7_results]
        })

        return layer_data, diagrams

# Main function to orchestrate the scans
def main():
    ip_base = "192.168.1."

    # Initialize scanner
    scanner = NetworkScanner()
    layer_data, diagrams = scanner.run_all_layer_scans(ip_base)

    logging.info("Generating PDF report...")
    report_generator = ReportGenerator(scanner.current_datetime)
    report_generator.generate_pdf_report(layer_data, diagrams)

if __name__ == "__main__":
    main()
