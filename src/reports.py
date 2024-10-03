# Generate PDF report with NetworkX Diagram

# import scapy.all as scapy
# import socket
# import psutil
# import threading
# from datetime import datetime
# import networkx as nx
# import matplotlib.pyplot as plt
# from io import BytesIO
# import tempfile
# import warnings

import logging
from fpdf import FPDF
from pathlib import Path
import os

class ReportGenerator:
    def __init__(self, current_datetime):
        self.current_datetime = current_datetime
        self.reports_folder = Path(__file__).parent.parent / "reports"
        self.reports_folder.mkdir(exist_ok=True)

    # Generate PDF report with NetworkX Diagram
    def generate_pdf_report(self,layer_data, diagrams=None):
        try:
            if diagrams is None:
                diagrams = {}

            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            
            # Title Page
            pdf.add_page()
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(200, 10, "Network Scan Report", ln=True, align="C")
            
            # Introduction
            pdf.set_font("Arial", size=12)
            pdf.ln(10)
            pdf.cell(200, 10, f"This report details the results of OSI Layer 1-7 network scans as of {self.current_datetime}.", ln=True)
            
            # Layer Data Reporting
            for layer in layer_data:
                pdf.ln(10)
                pdf.set_font("Arial", 'B', 14)
                pdf.cell(200, 10, f"{layer['title']}", ln=True)
                pdf.set_font("Arial", size=12)
                pdf.multi_cell(0, 10, layer['description'])
                
                # Add results if any
                pdf.ln(5)
                if layer['data'] != []:
                    for result in layer['data']:
                        pdf.multi_cell(0, 10, f"{result}")
                else:
                    pdf.cell(200, 10, "No data available or scan failed.", ln=True)

                # Embed the diagram for the layer if available
                if layer['title'] in diagrams:
                    pdf.add_page()
                    pdf.set_font("Arial", 'B', 14)
                    pdf.cell(200, 10, f"{layer['title']} Network Diagram", ln=True)
                    pdf.ln(10)
                    diagram_path = diagrams[layer['title']]
                    pdf.image(diagram_path, x=10, y=None, w=180)  # Embed the image file into the PDF
                    os.remove(diagram_path)  # Clean up the temporary image file

            # Save the PDF in the reports folder
            report_path = self.reports_folder / f"network_scan_report_{self.current_datetime}.pdf"
            pdf.output(str(report_path))
            logging.info(f"PDF report generated successfully at: {report_path}")
        except Exception as e:
            logging.error(f"Failed to generate PDF report: {e}")