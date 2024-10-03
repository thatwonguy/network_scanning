# Generate PDF report with NetworkX Diagram

import networkx as nx
import matplotlib.pyplot as plt
import tempfile
import os
import logging

class DiagramGenerator:
    @staticmethod
    def generate_network_diagram(devices, layer_title):
        try:
            # Create a graph
            G = nx.Graph()

            # Add nodes and edges to the graph based on the devices
            for device in devices:
                G.add_node(device['ip'], label=device['name'])

            # Create edges between devices if necessary (for simplicity, assume connections between devices)
            for i, device1 in enumerate(devices):
                for j, device2 in enumerate(devices):
                    if i != j:
                        G.add_edge(device1['ip'], device2['ip'])

            # Draw the graph
            plt.figure(figsize=(10, 8))
            pos = nx.spring_layout(G, k=0.5, seed=42)  # Adjust layout for better visualization and spacing
            labels = nx.get_node_attributes(G, 'label')
            
            # Draw nodes and edges
            nx.draw(G, pos, with_labels=False, node_color='skyblue', node_size=2000, font_size=10, font_weight='bold')
            
            # Draw labels separately to avoid overlap with nodes
            nx.draw_networkx_labels(G, pos, labels=labels, font_size=10, verticalalignment='bottom')

            # Add title to the plot
            plt.title(f"{layer_title} Diagram")

            # Save the diagram as a temporary file
            temp_image_path = tempfile.mktemp(suffix=".png")
            plt.savefig(temp_image_path, format='png')
            plt.close()
            
            logging.info(f"{layer_title} diagram generated successfully.")
            return temp_image_path
        except Exception as e:
            logging.error(f"Failed to generate {layer_title} diagram: {e}")
            return None