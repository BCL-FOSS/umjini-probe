from utils.network_utils.NetworkDiscovery import NetworkDiscovery
from utils.network_utils.NetworkSNMP import NetworkSNMP
from utils.network_utils.ProbeInfo import ProbeInfo
import ipaddress
from scapy.all import *
from scapy import *
from scapy.tools import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.layers.dns import *
import os
import time
from utils.network_utils.NetworkWiFi import NetworkkWiFi
import asyncio
import asyncio
import os
from fpdf import FPDF
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import time
from io import BytesIO
from asyncio import Task
import logging

class NetUtil():
    surveying = False
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('passlib').setLevel(logging.ERROR)
        
    def __init__(self, interface: str):
        self.iface = interface
        self.wifi=NetworkkWiFi(interface=self.iface)
        self.discovery = NetworkDiscovery()
        self.snmp = NetworkSNMP()
        self.ROLE_PORTS = { 
            # Ports that help fingerself.logger devices
            "firewall": [22, 443],
            "switch": [161, 22],
            "server": [22, 80, 443, 3389],
            "endpoint": [80, 443]
        }
        self.logger = logging.getLogger(__name__)

    def predict_role(self, open_ports, snmp_info):
        """Predict role based on open ports and SNMP data."""
        if snmp_info:
            descr = str(snmp_info.get('if_descr', '')).lower()
            if 'switch' in descr or 'uplink' in descr:
                return "switch"
            if 'firewall' in descr:
                return "firewall"
        if 161 in open_ports:
            return "switch"
        if 22 in open_ports and 443 in open_ports:
            return "firewall"
        if 3389 in open_ports:
            return "server"
        return "endpoint"

    async def full_discovery(self, action: str, interface: str, subnet: str):
        # Step 1: Layer 2 ARP Discovery
        devices_raw = self.discovery.discover_devices(iface=interface, action=action,
                                                params={"interface": interface, "subnet_cidr": subnet})
        if not devices_raw:
            return {}

        devices = {}
        for key, device in devices_raw.items():
            ip = device['ip']
            mac = device['mac']
            vendor = device['vendor']

            # Step 2: TCP ACK + Xmas + IP scans
            open_ports = []
          
            ans, ack_ans, ack_unans = self.discovery.scan_ack(ip, [21, 22, 25, 53, 68, 80, 443, 161, 3389])
            xmas_ans, _ = self.discovery.scan_xmas(ip)
            ip_ans, _ = self.discovery.scan_ip(ip)

            for pkt in ans:
                open_ports.append(pkt[0][TCP].dport)

            # Step 3: SNMP discovery
            snmp_info = {}
         
            snmp_devices = await self.snmp.discover_snmp_devices([ipaddress.ip_address(ip)])
            if ip in snmp_devices:
                snmp_info = {
                    "if_descr": await self.snmp.get(ip, self.snmp.OIDS["if_descr"])
                }
         
            # Step 4: Predict role
            role = self.predict_role(open_ports, snmp_info)

            # Step 5: Build final profile
            devices[ip] = {
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "open_ports": open_ports,
                "unfiltered_ports": ack_ans,
                "filtered_ports": ack_unans,
                "snmp_info": snmp_info,
                "role": role
            }

        return devices

    async def background_survey(self):
        global surveying
        while surveying is True:
            await asyncio.get_event_loop().run_in_executor(None, self.wifi.start_sniffing, 10)
            await asyncio.sleep(2)

    def start_survey(self):
        global surveying
        if surveying is False:
            self.wifi.enable_monitor_mode()
            surveying = True
            task = asyncio.create_task(self.background_survey())
            return True if isinstance(task, Task) else False
    
    def stop_survey(self):
        global surveying
        if surveying is True:
            surveying = False
            self.wifi.disable_monitor_mode()
        return {"status": "Survey stopped"}
      
    def generate_report(self):
        points = self.wifi.get_survey_json()
        if points is None:
            return None

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        pdf.set_font("Arial", 'B', 16)
        pdf.cell(0, 10, "WiFi Survey Report", ln=True, align='C')

        pdf.set_font("Arial", '', 12)
        pdf.cell(0, 10, f"Generated on {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}", ln=True)
        pdf.ln(10)

        aps = [p for p in points if p['type'] == 'AP']
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, "Access Points Detected:", ln=True)
        pdf.set_font("Arial", '', 11)
        for ap in aps:
            ssid = ap['ssid'] or "Hidden"
            pdf.multi_cell(0, 8, f"SSID: {ssid}, MAC: {ap['mac']}, SNR: {ap['snr']} dB, Manufacturer: {ap['manufacturer']}")

        pdf.add_page()
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, "Coverage Heatmap Snapshot:", ln=True)

        fig, ax = plt.subplots()
        good = [p for p in aps if p.get('coverage') == 'Good']
        fair = [p for p in aps if p.get('coverage') == 'Fair']
        poor = [p for p in aps if p.get('coverage') == 'Poor']

        if good:
            ax.scatter([p['x'] for p in good], [p['y'] for p in good], c='green', label='Good')
        if fair:
            ax.scatter([p['x'] for p in fair], [p['y'] for p in fair], c='yellow', label='Fair')
        if poor:
            ax.scatter([p['x'] for p in poor], [p['y'] for p in poor], c='red', label='Poor')

        ax.set_xlabel("Latitude / Signal")
        ax.set_ylabel("Longitude / Frequency")
        ax.set_title("Coverage Classification")
        ax.legend()

        img_data = BytesIO()
        plt.savefig(img_data, format='png')
        img_data.seek(0)
        plt.close(fig)

        pdf.image(img_data, x=10, y=40, w=180)

        output_path = f"{self.wifi.HISTORY_DIR}/wifi_survey_report.pdf"
        pdf.output(output_path)
        if os.path.exists(output_path):
            return output_path
        else:
            return None
        
    def get_survey_json(self):
        points = self.wifi.get_survey_json()
        if points is None:
            return None
    