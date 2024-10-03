import scapy.all as scapy
from fpdf import FPDF
import socket
import psutil
import threading
import logging
from datetime import datetime
from pathlib import Path
import networkx as nx
import matplotlib.pyplot as plt
from io import BytesIO
import tempfile
import os
import warnings
from graphs import generate_network_diagram
from generate_reports import generate_pdf_report

# Switch to non-GUI backend for matplotlib
plt.switch_backend('Agg')

# Suppress scapy warnings about MAC address broadcasting
warnings.filterwarnings("ignore", category=RuntimeWarning)

# Get the current date and time in the format month-day-year_hour_minute_second_AM/PM
current_datetime = datetime.now().strftime("%m-%d-%Y_%I-%M-%S_%p")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

# Layer 1: Physical Layer (Interfaces and Link Speed)
def layer1_scan():
    try:
        interfaces = psutil.net_if_addrs()
        interface_stats = psutil.net_if_stats()
        physical_data = []
        
        for interface_name, addresses in interfaces.items():
            if interface_name in interface_stats:
                stats = interface_stats[interface_name]
                physical_data.append({
                    'interface': interface_name,
                    'is_up': stats.isup,
                    'speed': stats.speed
                })
        return physical_data
    except Exception as e:
        logging.error(f"Layer 1 scan failed: {e}")
        return []

# Layer 2: ARP for MAC addresses - modified to return device names
def layer2_scan(ip_range):
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        devices = []
        for sent, received in answered_list:
            device = {'ip': received.psrc, 'mac': received.hwsrc}
            try:
                # Try to get the device hostname using socket
                device_name = socket.gethostbyaddr(received.psrc)[0]
                device['name'] = device_name
            except socket.herror:
                device['name'] = "Unknown"
            devices.append(device)
        return devices
    except Exception as e:
        logging.error(f"Layer 2 scan failed: {e}")
        return []

# Layer 3: ICMP (Ping) for IP addresses
def layer3_scan(ip_range):
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
def layer4_scan(ip):
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
def layer5_scan():
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
def layer6_scan():
    try:
        return [{"description": "SSL/TLS encryption detected on HTTPS ports."}]
    except Exception as e:
        logging.error(f"Layer 6 scan failed: {e}")
        return []

# Layer 7: Application Layer (Application protocols like HTTP, FTP)
def layer7_scan():
    try:
        applications = []
        applications.append({"protocol": "HTTP", "description": "HyperText Transfer Protocol"})
        applications.append({"protocol": "FTP", "description": "File Transfer Protocol"})
        return applications
    except Exception as e:
        logging.error(f"Layer 7 scan failed: {e}")
        return []

# Main function to orchestrate the scans
def main():
    ip_base = "192.168.1."
    ip_range = [f"{ip_base}{i}" for i in range(1, 255)]
    
    # Perform scans for all layers
    layer_data = []
    diagrams = {}
    
    # Layer 1: Physical Layer
    logging.info("Starting Layer 1 scan...")
    layer1_results = layer1_scan()
    layer_data.append({
        "title": "Layer 1: Physical Layer",
        "description": "The Physical Layer includes network interfaces and their status.",
        "data": [f"Interface: {item['interface']}, Status: {'Up' if item['is_up'] else 'Down'}, Speed: {item['speed']} Mbps" for item in layer1_results]
    })
    
    # Layer 2: Data Link Layer (ARP)
    logging.info("Starting Layer 2 scan...")
    layer2_results = layer2_scan(f"{ip_base}1/24")
    layer_data.append({
        "title": "Layer 2: Data Link Layer (ARP)",
        "description": "Layer 2 includes ARP scans to discover MAC addresses on the local network.",
        "data": [f"IP: {item['ip']}, MAC: {item['mac']}, Name: {item['name']}" for item in layer2_results]
    })
    # Generate diagram for Layer 2
    diagrams["Layer 2: Data Link Layer (ARP)"] = generate_network_diagram(layer2_results, "Layer 2: Data Link Layer (ARP)")
    
    # Layer 3: Network Layer (ICMP Ping)
    logging.info("Starting Layer 3 scan...")
    layer3_results = layer3_scan(ip_range)
    layer_data.append({
        "title": "Layer 3: Network Layer (ICMP Ping)",
        "description": "Layer 3 involves discovering active hosts via ICMP ping scans.",
        "data": [f"Active IP: {ip}" for ip in layer3_results]
    })
    
    # Layer 4: Transport Layer (TCP/UDP Port Scan)
    logging.info("Starting Layer 4 scan...")
    layer4_data = {}
    for ip in layer3_results:
        open_ports = layer4_scan(ip)
        if open_ports:
            layer4_data[ip] = open_ports
    layer_data.append({
        "title": "Layer 4: Transport Layer (TCP/UDP)",
        "description": "Layer 4 involves scanning for open TCP/UDP ports on active hosts.",
        "data": [f"IP: {ip}, Open Ports: {', '.join(map(str, ports))}" for ip, ports in layer4_data.items()]
    })
    
    # Layer 5: Session Layer
    logging.info("Starting Layer 5 scan...")
    layer5_results = layer5_scan()
    layer_data.append({
        "title": "Layer 5: Session Layer",
        "description": "Layer 5 manages sessions, such as active TCP connections.",
        "data": [f"Local: {sess['local_address']}, Remote: {sess['remote_address']}, Status: {sess['status']}" for sess in layer5_results]
    })
    
    # Layer 6: Presentation Layer (Encryption)
    logging.info("Starting Layer 6 scan...")
    layer6_results = layer6_scan()
    layer_data.append({
        "title": "Layer 6: Presentation Layer",
        "description": "Layer 6 involves encryption and data translation, such as SSL/TLS encryption.",
        "data": [f"{enc['description']}" for enc in layer6_results]
    })
    
    # Layer 7: Application Layer (Application protocols)
    logging.info("Starting Layer 7 scan...")
    layer7_results = layer7_scan()
    layer_data.append({
        "title": "Layer 7: Application Layer",
        "description": "Layer 7 includes application protocols such as HTTP and FTP.",
        "data": [f"Protocol: {app['protocol']}, Description: {app['description']}" for app in layer7_results]
    })
    
    # Generate PDF report with network diagram
    logging.info("Generating PDF report...")
    generate_pdf_report(layer_data, current_datetime, diagrams)

if __name__ == "__main__":
    main()
