import scapy.all as scapy
import networkx as nx
import matplotlib.pyplot as plt
from scapy.layers.l2 import ARP, Ether
import os

# Function to perform ARP scan on the local network
def scan_network(ip_range):
    # Create an ARP request packet
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast request to all devices
    arp_request_broadcast = broadcast / arp_request
    
    # Send the request and capture responses
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    devices = []
    for sent, received in answered_list:
        device_info = {
            'ip': received.psrc,
            'mac': received.hwsrc,
            'status': 'Online'
        }
        devices.append(device_info)
    return devices

# Function to generate a network diagram
def generate_network_diagram(devices):
    G = nx.Graph()
    
    # Add devices as nodes with IP and MAC labels
    for device in devices:
        G.add_node(device['ip'], label=f"{device['ip']}\n{device['mac']}")
    
    # Randomly connect devices for simplicity (for a more accurate mapping, specific logic is required)
    for i in range(len(devices) - 1):
        G.add_edge(devices[i]['ip'], devices[i + 1]['ip'])
    
    return G

# Main function to perform network scan and visualize the results
def main():
    # You need to specify the range of IP addresses to scan (replace with your network range)
    ip_range = "192.168.1.1/24"
    
    # Scan the network
    devices = scan_network(ip_range)
    
    print("Devices Found:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
    
    # Generate network diagram
    G = generate_network_diagram(devices)
    
    # Visualize the network
    pos = nx.spring_layout(G)  # Layout for the graph
    labels = nx.get_node_attributes(G, 'label')
    nx.draw(G, pos, with_labels=False, node_size=3000, node_color='skyblue')
    nx.draw_networkx_labels(G, pos, labels=labels)
    
    plt.title("Real Network Diagram")
    plt.show()

if __name__ == "__main__":
    # Ensure running with admin privileges
    if os.name == "nt" and not os.geteuid() == 0:
        print("Please run this script as an Administrator.")
    main()
